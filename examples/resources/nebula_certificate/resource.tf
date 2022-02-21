resource "nebula_certificate" "node1" {
  name       = "node1"
  groups     = ["nodes"]
  ip         = "192.168.0.1/24"
  ca_cert    = nebula_ca.awesome.cert
  ca_key     = nebula_ca.awesome.key
  public_key = <<-EOF
		-----BEGIN NEBULA X25519 PUBLIC KEY-----
		cKqs1nDULzxs7rbEW5p+N7z5/hG34IrRQ3yOS4xvaxs=
		-----END NEBULA X25519 PUBLIC KEY-----
	EOF

  duration               = "24h"
  early_renewal_duration = "1h"
}

resource "nebula_certificate" "node2" {
  name    = "test1"
  groups  = ["nodes", "laptops"]
  ip      = "192.168.0.1/24"
  subnets = ["192.168.0.1/26"]
  ca_cert = nebula_ca.awesome.cert
  ca_key  = nebula_ca.awesome.key

  duration               = "24h"
  early_renewal_duration = "1h"
}
