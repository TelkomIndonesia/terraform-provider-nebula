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
