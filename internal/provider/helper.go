package provider

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"
)

func isValidDuration(i interface{}, p cty.Path) (dg diag.Diagnostics) {
	v, ok := i.(string)
	if !ok {
		return diag.Errorf("Invalid value")
	}
	if _, err := time.ParseDuration(v); err != nil {
		return diag.Errorf("Invalid time duration")
	}
	return
}

func stringToIP(rs string, isNet bool) (ipNet *net.IPNet, err error) {
	ip, ipNet, err := net.ParseCIDR(rs)
	if err != nil {
		return nil, fmt.Errorf("invalid ip/subnet definition: %s", err)
	}
	if !isNet {
		ipNet.IP = ip
	}
	if ipNet.IP.To4() == nil {
		return nil, fmt.Errorf("invalid ip/subnet definition: can only be IPv4, have %s", rs)
	}
	return ipNet, nil
}

func stringsToIPs(rs []string, isNet bool) (ips []*net.IPNet, err error) {
	for _, s := range rs {
		ip, err := stringToIP(s, isNet)
		if err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return
}

func toCert(crt []byte) (nCert *cert.NebulaCertificate, err error) {
	nCert, _, err = cert.UnmarshalNebulaCertificateFromPEM(crt)
	if err != nil {
		return nil, fmt.Errorf("error while parsing crt: %s", err)
	}
	if _, err := nCert.Sha256Sum(); err != nil {
		return nil, fmt.Errorf("error while getting fingerprint: %s", err)
	}

	return
}

func toCAPair(key []byte, crt []byte) (caKey ed25519.PrivateKey, caCert *cert.NebulaCertificate, err error) {
	if caCert, err = toCert(crt); err != nil {
		return nil, nil, err
	}
	if caKey, _, err = cert.UnmarshalEd25519PrivateKey(key); err != nil {
		return nil, nil, fmt.Errorf("error while parsing key: %s", err)
	}
	if err := caCert.VerifyPrivateKey(caKey); err != nil {
		return nil, nil, fmt.Errorf("refusing to load certificate, root certificate does not match private key")
	}
	return
}

func toCertPair(key []byte, crt []byte) (nKey ed25519.PrivateKey, nCert *cert.NebulaCertificate, err error) {
	if nCert, err = toCert(crt); err != nil {
		return nil, nil, err
	}
	if nKey, _, err = cert.UnmarshalX25519PrivateKey(key); err != nil {
		return nil, nil, fmt.Errorf("error while parsing key: %s", err)
	}
	if err := nCert.VerifyPrivateKey(nKey); err != nil {
		return nil, nil, fmt.Errorf("refusing to load certificate, root certificate does not match private key")
	}
	return
}

func x25519Keypair() ([]byte, []byte, error) {
	privkey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, privkey); err != nil {
		return nil, nil, err
	}

	pubkey, err := curve25519.X25519(privkey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}

	return pubkey, privkey, err
}

func shouldExpire(c *cert.NebulaCertificate, early time.Duration) bool {
	tn := time.Now()
	te := c.Details.NotAfter.Add(-early)
	return te.Before(tn) || c.Expired(tn)
}

func ipsToString(ips []*net.IPNet) (s []string) {
	for _, ip := range ips {
		s = append(s, ip.String())
	}
	return
}
