package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
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
