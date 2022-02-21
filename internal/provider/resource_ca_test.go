package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
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
