package provider

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAccResourceCA(t *testing.T) {

	resource.UnitTest(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceCA,
			},
			{
				Config:             testAccResourceCAExpired,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

const testAccResourceCA = `
	resource "nebula_ca" "test" {
		name = "test"
	}

	resource "nebula_ca" "test1" {
		name = "test1"
		groups = ["test12"]
		ips = ["192.168.0.1/24"]
		subnets = ["192.168.0.1/26"]
		duration = "24h"
		early_renewal_duration = "1h"
	}
`

const testAccResourceCAExpired = `
	resource "nebula_ca" "testexp" {
		name = "test"
		duration="0.000000001s"
	}

	resource "nebula_ca" "testexp1" {
		name = "test"
		duration = "24h"
		early_renewal_duration = "24h"
	}
`

// WARN: Possible flaky test
func TestAccResourceCAUpdateEarlyRenewal(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceCAUpdateEarlyRenewal,
			},
			{
				Config: testAccResourceCAUpdateEarlyRenewalUpdate,
			},
		},
	})
}

const testAccResourceCAUpdateEarlyRenewal = `
	resource "nebula_ca" "test" {
		name = "test"
		duration = "24h"
		provisioner "local-exec" {
			interpreter = ["bash", "-c"]
			command = "sleep 5"
		}
	}
`
const testAccResourceCAUpdateEarlyRenewalUpdate = `
	resource "nebula_ca" "test" {
		name = "test"
		duration = "24h"
		early_renewal_duration = "23h59m55s"
	}
`

func TestAccResourceCAImport(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceCAImport,
			},
			{
				ResourceName:  "nebula_ca.test",
				ImportState:   true,
				ImportStateId: filepath.Join("testdata", "ca.key") + ":" + filepath.Join("testdata", "ca.crt"),
				ImportStateCheck: func(is []*terraform.InstanceState) error {
					rawCAKey, err := ioutil.ReadFile("testdata/ca.key")
					if err != nil {
						return fmt.Errorf("error while reading ca-key: %s", err)
					}
					rawCACert, err := ioutil.ReadFile("testdata/ca.crt")
					if err != nil {
						return fmt.Errorf("error while reading ca-crt: %s", err)
					}
					fp := "0d16860ca3125cfc3da3b21cf13bad3ae04be3fb7574e54e01f4c92520151574"

					state := is[0]
					if v := state.Attributes["id"]; v != fp {
						return fmt.Errorf("invalid id, got %s", v)
					}
					if v := state.Attributes["fingerprint"]; v != fp {
						return fmt.Errorf("invalid fingerprint, got %s", v)
					}
					if v := state.Attributes["key"]; v != string(rawCAKey) {
						return fmt.Errorf("invalid private key, got %s", v)
					}
					if v := state.Attributes["cert"]; v != string(rawCACert) {
						return fmt.Errorf("invalid certificate, got %s", v)
					}
					if v := state.Attributes["not_after"]; v != "2023-02-24T13:47:48+07:00" {
						return fmt.Errorf("invalid not_after, got %s", v)
					}
					if v := state.Attributes["not_before"]; v != "2022-02-24T13:47:48+07:00" {
						return fmt.Errorf("invalid not_before, got %s", v)
					}
					return nil
				},
			},
			{
				Config:   testAccResourceCAImport,
				PlanOnly: true,
			},
		},
	})
}

const testAccResourceCAImport = `
	resource "nebula_ca" "test" {
		name = "test"
		ips = ["192.168.1.0/26"]
		subnets = ["192.168.1.0/24"]
		groups = ["test","test1"]
	}
`
