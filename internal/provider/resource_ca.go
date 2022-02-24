package provider

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/slackhq/nebula/cert"
	"github.com/spf13/cast"
)

func resourceCA() *schema.Resource {
	return &schema.Resource{
		Description: "Create a self signed certificate authority",

		ReadContext:   resourceCARead,
		CreateContext: resourceCACreate,
		UpdateContext: resourceCAUpdate,
		DeleteContext: resourceCADelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceCAImport,
		},
		CustomizeDiff: resourceCADiff,

		Schema: map[string]*schema.Schema{
			"name": {
				Description:      "Name of the certificate authority.",
				Type:             schema.TypeString,
				Required:         true,
				ForceNew:         true,
				ValidateDiagFunc: validation.ToDiagFunc(validation.StringIsNotEmpty),
			},
			"groups": {
				Description: "List of groups. This will limit which groups subordinate certs can use.",
				Type:        schema.TypeList,
				Elem: &schema.Schema{
					Type:         schema.TypeString,
					ValidateFunc: validation.StringIsNotEmpty,
				},
				Optional: true,
				ForceNew: true,
			},
			"ips": {
				Description: "List of IPv4 address and network in CIDR notation. This will limit which IPv4 addresses and networks subordinate certs can use for ip addresses.",
				Type:        schema.TypeList,
				Elem: &schema.Schema{
					Type:         schema.TypeString,
					ValidateFunc: validation.IsCIDR,
				},
				Optional: true,
				ForceNew: true,
			},
			"subnets": {
				Description: "List of IPv4 address and network in CIDR notation. This will limit which IPv4 addresses and networks subordinate certs can use in subnets.",
				Type:        schema.TypeList,
				Elem: &schema.Schema{
					Type:         schema.TypeString,
					ValidateFunc: validation.IsCIDR,
				},
				Optional: true,
				ForceNew: true,
			},
			"duration": {
				Description:      "amount of time the certificate should be valid for. Valid time units are seconds: \"s\", minutes: \"m\", hours: \"h\".",
				Type:             schema.TypeString,
				Default:          "8760h0m0s",
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

			"cert": {
				Description: "The certificate data in PEM format.",
				Type:        schema.TypeString,
				Computed:    true,
			},
			"key": {
				Description: "The private key data in PEM format.",
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

func resourceCARead(ctx context.Context, d *schema.ResourceData, meta interface{}) (dg diag.Diagnostics) {
	_, caCert, err := toCAPair([]byte(cast.ToString(d.Get("key"))), []byte(cast.ToString(d.Get("cert"))))
	if err != nil {
		return diag.Errorf("error loading CA pair: %s", err)
	}

	if shouldExpire(caCert, cast.ToDuration(d.Get("early_renewal_duration"))) {
		d.SetId("")
	}
	return
}

func resourceCACreate(ctx context.Context, d *schema.ResourceData, meta interface{}) (dg diag.Diagnostics) {
	ips, err := stringsToIPs(cast.ToStringSlice(d.Get("ips")), false)
	if err != nil {
		diag.FromErr(err)
	}
	subnets, err := stringsToIPs(cast.ToStringSlice(d.Get("subnets")), true)
	if err != nil {
		diag.FromErr(err)
	}

	pub, rawPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return diag.Errorf("error while generating ed25519 keys: %s", err)
	}
	nc := cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name:      cast.ToString(d.Get("name")),
			Groups:    cast.ToStringSlice(d.Get("groups")),
			Ips:       ips,
			Subnets:   subnets,
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(cast.ToDuration(d.Get("duration"))),
			PublicKey: pub,
			IsCA:      true,
		},
	}
	if err = nc.Sign(rawPriv); err != nil {
		return diag.Errorf("error while signing: %s", err)
	}

	crt, err := nc.MarshalToPEM()
	if err != nil {
		return diag.Errorf("error while marshalling certificate: %s", err)
	}
	d.Set("cert", string(crt))
	d.Set("key", string(cert.MarshalEd25519PrivateKey(rawPriv)))
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

func resourceCADelete(ctx context.Context, d *schema.ResourceData, meta interface{}) (dg diag.Diagnostics) {
	d.SetId("")
	return
}

func resourceCAUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) (dg diag.Diagnostics) {
	return
}

func resourceCADiff(ctx context.Context, rd *schema.ResourceDiff, meta interface{}) (err error) {
	if rd.Id() == "" {
		return // no state
	}
	for _, v := range []string{"name", "groups", "ips", "subnets", "duration"} {
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

func resourceCAImport(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	paths := filepath.SplitList(d.Id())
	if len(paths) != 2 {
		return nil, fmt.Errorf("Argument must be in the form of <path-to-ca-key-file>:<path-to-ca-cert-file>. Got %s", d.Id())
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

	fp, err := caCert.Sha256Sum()
	if err != nil {
		return nil, fmt.Errorf("error while getting certificate fingerprint: %s", err)
	}
	d.Set("name", caCert.Details.Name)
	d.Set("groups", caCert.Details.Groups)
	d.Set("ips", ipsToString(caCert.Details.Ips))
	d.Set("subnets", ipsToString(caCert.Details.Subnets))
	d.Set("cert", string(rawCACert))
	d.Set("key", string(rawCAKey))
	d.Set("not_after", caCert.Details.NotAfter.Format(time.RFC3339))
	d.Set("not_before", caCert.Details.NotBefore.Format(time.RFC3339))
	d.Set("fingerprint", fp)
	d.SetId(fp)

	return []*schema.ResourceData{d}, nil
}
