package provider

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/spf13/cast"
)

func TestAccResourceCertificate(t *testing.T) {

	resource.UnitTest(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceCertificate,
			},
			{
				Config:             testAccResourceCertificateExpired,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

const testAccResourceCertificate = `
	resource "nebula_ca" "test" {
		name = "test"
	}

	resource "nebula_certificate" "test1" {
		name = "test1"
		ip = "192.168.0.1/24"
		ca_cert = nebula_ca.test.cert
		ca_key = nebula_ca.test.key
	}

	resource "nebula_certificate" "test2" {
		name = "test1"
		ip = "192.168.0.1/24"
		ca_cert = nebula_ca.test.cert
		ca_key = nebula_ca.test.key
		public_key = <<-EOF
			-----BEGIN NEBULA X25519 PUBLIC KEY-----
			cKqs1nDULzxs7rbEW5p+N7z5/hG34IrRQ3yOS4xvaxs=
			-----END NEBULA X25519 PUBLIC KEY-----
		EOF
	}

	resource "nebula_certificate" "test3" {
		name = "test1"
		groups = ["test12"]
		ip = "192.168.0.1/24"
		subnets = ["192.168.0.1/26"]
		ca_cert = nebula_ca.test.cert
		ca_key = nebula_ca.test.key

		duration = "24h"
		early_renewal_duration = "1h"
	}
`

const testAccResourceCertificateExpired = `
	resource "nebula_ca" "testexp" {
		name = "test"
	}

	resource "nebula_certificate" "testexp" {
		name = "test"
		ip = "192.168.0.1/24"
		ca_cert = nebula_ca.testexp.cert
		ca_key = nebula_ca.testexp.key
		duration="0.000000001s"
	}

	resource "nebula_certificate" "testexp1" {
		name = "test"
		ip = "192.168.0.1/24"
		ca_cert = nebula_ca.testexp.cert
		ca_key = nebula_ca.testexp.key
		duration="24h"
		early_renewal_duration="24h"
	}
`

// WARN: Possible flaky test
func TestAccResourceCertificateUpdateEarlyRenewal(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceCertificateUpdateEarlyRenewal,
			},
			{
				Config: testAccResourceCertificateUpdateEarlyRenewalUpdate,
			},
		},
	})
}

const testAccResourceCertificateUpdateEarlyRenewal = `
	resource "nebula_ca" "testexp" {
		name = "test"
	}
	resource "nebula_certificate" "testexp" {
		name = "test"
		ip = "192.168.0.1/24"
		ca_cert = nebula_ca.testexp.cert
		ca_key = nebula_ca.testexp.key
		duration="24h"
		
		provisioner "local-exec" {
			interpreter = ["bash", "-c"]
			command = "sleep 5"
		}
	}
`
const testAccResourceCertificateUpdateEarlyRenewalUpdate = `
	resource "nebula_ca" "testexp" {
		name = "test"
	}
	resource "nebula_certificate" "testexp" {
		name = "test"
		ip = "192.168.0.1/24"
		ca_cert = nebula_ca.testexp.cert
		ca_key = nebula_ca.testexp.key
		duration="24h"
		early_renewal_duration = "23h59m55s"
	}
`

func TestAccResourceCertificateImport(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceCertificateImport,
			},
			{
				ResourceName:  "nebula_ca.test",
				ImportState:   true,
				ImportStateId: filepath.Join("testdata", "ca.key") + ":" + filepath.Join("testdata", "ca.crt"),
			},
			{

				ResourceName: "nebula_certificate.test",
				ImportState:  true,
				ImportStateId: filepath.Join("testdata", "ca.key") + ":" + filepath.Join("testdata", "ca.crt") + ":" +
					filepath.Join("testdata", "test.key") + ":" + filepath.Join("testdata", "test.crt"),
				ImportStateCheck: func(is []*terraform.InstanceState) error {
					rawCAKey, err := ioutil.ReadFile("testdata/test.key")
					if err != nil {
						return fmt.Errorf("error while reading key: %s", err)
					}
					rawCACert, err := ioutil.ReadFile("testdata/test.crt")
					if err != nil {
						return fmt.Errorf("error while reading certificate: %s", err)
					}
					fp := "f4e0d87d83480dd51d4e29bf2a32c06c337fadc8257ece2ed32f6516f8ceca64"

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
					if v := cast.ToTime(state.Attributes["not_after"]); !v.Equal(cast.ToTime("2023-02-24T13:47:47+07:00")) {
						return fmt.Errorf("invalid not_after, got %s", v)
					}
					if v := cast.ToTime(state.Attributes["not_before"]); !v.Equal(cast.ToTime("2022-02-24T13:47:58+07:00")) {
						return fmt.Errorf("invalid not_before, got %s", v)
					}
					return nil
				},
			},
			{
				Config:   testAccResourceCertificateImport,
				PlanOnly: true,
			},
		},
	})
}

const testAccResourceCertificateImport = `
	resource "nebula_ca" "test" {
		name = "test"
		ips = ["192.168.1.0/26"]
		subnets = ["192.168.1.0/24"]
		groups = ["test","test1"]
	}

	resource "nebula_certificate" "test" {
		name = "test"
		ip = "192.168.1.1/26"
		subnets = ["192.168.1.0/24"]
		ca_cert = nebula_ca.test.cert
		ca_key = nebula_ca.test.key
		groups = ["test","test1"]
	}
`
