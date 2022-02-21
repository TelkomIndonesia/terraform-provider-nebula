resource "nebula_ca" "awesome" {
  name                   = "awesome"
  groups                 = ["nodes", "lighthouses", "laptops"]
  ips                    = ["192.168.0.1/24"]
  subnets                = ["192.168.0.1/26"]
  duration               = "24h"
  early_renewal_duration = "1h"
}
