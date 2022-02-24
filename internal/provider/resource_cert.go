package provider

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"path/filepath"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/slackhq/nebula/cert"
	"github.com/spf13/cast"
)

func resourceCertificate() *schema.Resource {
	return &schema.Resource{
		Description: "Create and sign a certificate",

		ReadContext:   resourceCertificateRead,
		CreateContext: resourceCertificateCreate,
		UpdateContext: resourceCertificateUpdate,
		DeleteContext: resourceCertificateDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceCertificateImport,
		},
		CustomizeDiff: resourceCertificateDiff,

		Schema: map[string]*schema.Schema{
			"name": {
				Description:      "Name of the cert, usually a hostname.",
				Type:             schema.TypeString,
				Required:         true,
				ForceNew:         true,
				ValidateDiagFunc: validation.ToDiagFunc(validation.StringIsNotEmpty),
			},
			"ip": {
				Description:      "IPv4 address and network in CIDR notation to assign the cert.",
				Type:             schema.TypeString,
				ValidateDiagFunc: validation.ToDiagFunc(validation.IsCIDR),
				Required:         true,
				ForceNew:         true,
			},
			"groups": {
				Description: "List of groups.",
				Type:        schema.TypeList,
				Elem: &schema.Schema{
					Type:         schema.TypeString,
					ValidateFunc: validation.StringIsNotEmpty,
				},
				Optional: true,
				ForceNew: true,
			},
			"subnets": {
				Description: "List of ipv4 address and network in CIDR notation. Subnets this cert can serve for.",
				Type:        schema.TypeList,
				Elem: &schema.Schema{
					Type:         schema.TypeString,
					ValidateFunc: validation.IsCIDR,
				},
				Optional: true,
				ForceNew: true,
			},
			"duration": {
				Description:      "how long the cert should be valid for. The default is 1 second before the signing cert expires. Valid time units are seconds: \"s\", minutes: \"m\", hours: \"h\".",
				Type:             schema.TypeString,
				Optional:         true,
				ValidateDiagFunc: isValidDuration,
				ForceNew:         true,
			},
			"early_renewal_duration": {
				Description:      "If set, the resource will consider the certificate to have expired the given durations before its actual expiry time. This can be useful to deploy an updated certificate in advance of the expiration of the current certificate. Note however that the old certificate remains valid until its true expiration time, since this resource does not (and cannot) support certificate revocation. Note also that this advance update can only be performed should the Terraform configuration be applied during the early renewal period.",
				Type:             schema.TypeString,
				Optional:         true,
				ValidateDiagFunc: isValidDuration,
			},
			"ca_cert": {
				Description: "The signing CA certificate data in PEM format.",
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
			},
			"ca_key": {
				Description: "The signing CA private key data in PEM format.",
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				ForceNew:    true,
			},
			"public_key": {
				Description: "The previously generated public key data in PEM format.",
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
			},

			"cert": {
				Description: "The certificate data in PEM format.",
				Type:        schema.TypeString,
				Computed:    true,
			},
			"key": {
				Description: "The private key data in PEM format. Empty if `public_key` is specified.",
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
			},
			"fingerprint": {
				Description: "The fingerprint of the certificate.",
				Type:        schema.TypeString,
				Computed:    true,
			},
			"not_after": {
				Description: "Certificate not valid after this date.",
				Type:        schema.TypeString,
				Computed:    true,
			},
			"not_before": {
				Description: "Certificate not valid after this date.",
				Type:        schema.TypeString,
				Computed:    true,
			},
		},
	}
}

func resourceCertificateRead(ctx context.Context, d *schema.ResourceData, meta interface{}) (dg diag.Diagnostics) {
	var err error
	var nCert *cert.NebulaCertificate
	if _, ok := d.GetOk("public_key"); ok {
		nCert, err = toCert([]byte(cast.ToString(d.Get("cert"))))
	} else {
		_, nCert, err = toCertPair([]byte(cast.ToString(d.Get("key"))), []byte(cast.ToString(d.Get("cert"))))
	}
	if err != nil {
		return diag.Errorf("error loading certificate pair: %s", err)
	}
	if shouldExpire(nCert, cast.ToDuration(d.Get("early_renewal_duration"))) {
		d.SetId("")
		return
	}

	_, caCert, err := toCAPair([]byte(cast.ToString(d.Get("ca_key"))), []byte(cast.ToString(d.Get("ca_cert"))))
	if err != nil {
		return diag.Errorf("error loading CA pair: %s", err)
	}
	if caCert.Expired(time.Now()) {
		d.SetId("")
		return
	}
	caPool := cert.NewCAPool()
	_, err = caPool.AddCACertificate([]byte(cast.ToString(d.Get("ca_cert"))))
	if err != nil {
		return diag.Errorf("error while adding CA cert to pool: %s", err)
	}
	good, err := nCert.Verify(time.Now(), caPool)
	if !good {
		return diag.Errorf("error verifying cert with CA : %s", err)
	}

	return
}
func resourceCertificateCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) (dg diag.Diagnostics) {
	caKey, caCert, err := toCAPair([]byte(cast.ToString(d.Get("ca_key"))), []byte(cast.ToString(d.Get("ca_cert"))))
	if err != nil {
		return diag.Errorf("error loading CA pair: %s", err)
	}
	if caCert.Expired(time.Now()) {
		return diag.Errorf("CA certificate is expired")
	}
	issuer, _ := caCert.Sha256Sum()

	ip, err := stringToIP(cast.ToString(d.Get("ip")), false)
	if err != nil {
		diag.FromErr(err)
	}
	subnets, err := stringsToIPs(cast.ToStringSlice(d.Get("subnets")), true)
	if err != nil {
		diag.FromErr(err)
	}
	dur := cast.ToDuration(d.Get("duration"))
	if dur <= 0 {
		dur = time.Until(caCert.Details.NotAfter) - time.Second*1
	}

	var pub, rawPriv []byte
	if v, ok := d.GetOk("public_key"); ok {
		pub, _, err = cert.UnmarshalX25519PublicKey([]byte(cast.ToString(v)))
	} else {
		pub, rawPriv, err = x25519Keypair()
	}
	if err != nil {
		return diag.FromErr(err)
	}

	nc := cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name:      cast.ToString(d.Get("name")),
			Ips:       []*net.IPNet{ip},
			Groups:    cast.ToStringSlice(d.Get("groups")),
			Subnets:   subnets,
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(dur),
			PublicKey: pub,
			IsCA:      false,
			Issuer:    issuer,
		},
	}
	if err := nc.CheckRootConstrains(caCert); err != nil {
		return diag.Errorf("refusing to sign, root certificate constraints violated: %s", err)
	}
	if err = nc.Sign(caKey); err != nil {
		return diag.Errorf("error while signing: %s", err)
	}

	crt, err := nc.MarshalToPEM()
	if err != nil {
		return diag.Errorf("error while marshalling certificate: %s", err)
	}
	d.Set("cert", string(crt))
	if rawPriv != nil {
		d.Set("key", string(cert.MarshalX25519PrivateKey(rawPriv)))
	}
	d.Set("not_after", nc.Details.NotAfter.Format(time.RFC3339))
	d.Set("not_before", nc.Details.NotBefore.Format(time.RFC3339))
	fp, err := nc.Sha256Sum()
	if err != nil {
		return diag.Errorf("error while getting certificate fingerprint: %s", err)
	}
	d.Set("fingerprint", fp)
	d.SetId(string(fp))
	return
}
func resourceCertificateDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) (dg diag.Diagnostics) {
	d.SetId("")
	return
}
func resourceCertificateUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) (dg diag.Diagnostics) {
	return
}

func resourceCertificateDiff(ctx context.Context, rd *schema.ResourceDiff, meta interface{}) (err error) {
	if rd.Id() == "" {
		return // no state
	}
	for _, v := range []string{"name", "groups", "ip", "subnets", "duration", "ca_cert", "ca_key", "public_key"} {
		if rd.HasChange(v) {
			return
		}
	}
	if !rd.HasChange("early_renewal_duration") {
		return
	}

	_, n := rd.GetChange("early_renewal_duration")
	exp := cast.ToTime(rd.Get("not_after")).Add(-cast.ToDuration(n))
	if time.Now().Before(exp) {
		return
	}
	rd.ForceNew("early_renewal_duration")
	return
}

func resourceCertificateImport(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	paths := filepath.SplitList(d.Id())
	if len(paths) < 4 {
		return nil, fmt.Errorf("Argument must be in the form of <path-to-ca-key-file>:<path-to-ca-cert-file>:{<path-to-private-key-file>|<path-to-public-key-file>}:<path-to-certificatefile>. Got %s", d.Id())
	}
	rawCAKey, err := ioutil.ReadFile(paths[0])
	if err != nil {
		return nil, fmt.Errorf("error while reading ca-key: %s", err)
	}
	rawCACert, err := ioutil.ReadFile(paths[1])
	if err != nil {
		return nil, fmt.Errorf("error while reading ca-crt: %s", err)
	}
	_, caCert, err := toCAPair(rawCAKey, rawCACert)
	if err != nil {
		return nil, fmt.Errorf("error loading CA pair: %s", err)
	}
	if caCert.Expired(time.Now()) {
		return nil, fmt.Errorf("ca certificate is expired")
	}

	rawCert, err := ioutil.ReadFile(paths[3])
	if err != nil {
		return nil, fmt.Errorf("error while reading certificate: %s", err)
	}
	nCert, err := toCert(rawCert)
	if err != nil {
		return nil, fmt.Errorf("error loading certificate: %s", err)
	}
	if nCert.Expired(time.Now()) {
		return nil, fmt.Errorf("ca certificate is expired")
	}
	caPool := cert.NewCAPool()
	_, err = caPool.AddCACertificate(rawCACert)
	if err != nil {
		return nil, fmt.Errorf("error while adding CA cert to pool: %s", err)
	}
	good, err := nCert.Verify(time.Now(), caPool)
	if !good {
		return nil, fmt.Errorf("error verifying cert with CA : %s", err)
	}

	rawKey, err := ioutil.ReadFile(paths[2])
	if err != nil {
		return nil, fmt.Errorf("error while reading private or public key: %s", err)
	}
	_, _, errPri := cert.UnmarshalX25519PrivateKey(rawKey)
	_, _, errPub := cert.UnmarshalX25519PublicKey(rawKey)
	if errPri != nil && errPub != nil {
		return nil, fmt.Errorf("error while loading private or public key: %s %s", errPri, errPub)
	}

	fp, err := nCert.Sha256Sum()
	if err != nil {
		return nil, fmt.Errorf("error while getting certificate fingerprint: %s", err)
	}
	d.Set("name", nCert.Details.Name)
	d.Set("groups", nCert.Details.Groups)
	d.Set("ip", nCert.Details.Ips[0].String())
	d.Set("subnets", ipsToString(nCert.Details.Subnets))
	d.Set("cert", string(rawCert))
	if errPri == nil {
		d.Set("key", string(rawKey))
	} else {
		d.Set("public_key", string(rawKey))
	}
	d.Set("ca_cert", string(rawCACert))
	d.Set("ca_key", string(rawCAKey))
	d.Set("not_after", nCert.Details.NotAfter.Format(time.RFC3339))
	d.Set("not_before", nCert.Details.NotBefore.Format(time.RFC3339))
	d.Set("fingerprint", fp)
	d.SetId(fp)

	return []*schema.ResourceData{d}, nil
}
