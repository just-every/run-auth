package provider

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func New() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"issuer":    {Type: schema.TypeString, Required: true, DefaultFunc: schema.EnvDefaultFunc("AUTH_ISSUER", nil), Description: "Auth HTTPS issuer origin; loopback HTTP is supported locally."},
			"client_id": {Type: schema.TypeString, Required: true, DefaultFunc: schema.EnvDefaultFunc("AUTH_CLIENT_ID", nil), Description: "Scoped Admin API service client ID."},
		},
		ConfigureContextFunc: func(_ context.Context, d *schema.ResourceData) (any, diag.Diagnostics) {
			c, err := newClient(d.Get("issuer").(string), d.Get("client_id").(string))
			return c, diag.FromErr(err)
		},
		ResourcesMap: map[string]*schema.Resource{"auth_group": group(), "auth_saml_app": app(), "auth_assignment": assignment()},
	}
}
func text(required, force bool) *schema.Schema {
	return &schema.Schema{Type: schema.TypeString, Required: required, Optional: !required, ForceNew: force, ValidateFunc: validation.StringLenBetween(1, 1024)}
}
func etag() *schema.Schema {
	return &schema.Schema{Type: schema.TypeString, Computed: true, Description: "Exact reviewed Auth administration revision; never retried on conflict."}
}
func resource(fields map[string]*schema.Schema, read schema.ReadContextFunc, create schema.CreateContextFunc, update schema.UpdateContextFunc, remove schema.DeleteContextFunc) *schema.Resource {
	fields["etag"] = etag()
	return &schema.Resource{Schema: fields, ReadContext: read, CreateContext: create, UpdateContext: update, DeleteContext: remove, Importer: &schema.ResourceImporter{StateContext: schema.ImportStatePassthroughContext}}
}
func set(d *schema.ResourceData, values map[string]any) diag.Diagnostics {
	for key, value := range values {
		if err := d.Set(key, value); err != nil {
			return diag.Errorf("cannot record Auth field %s", key)
		}
	}
	return nil
}
func missing(d *schema.ResourceData, err error) diag.Diagnostics {
	if e, ok := err.(*apiError); ok && e.status == 404 {
		d.SetId("")
		return nil
	}
	return diag.FromErr(err)
}
func pathID(id string) string             { return url.PathEscape(id) }
func tagOf(d *schema.ResourceData) string { return d.Get("etag").(string) }
func group() *schema.Resource {
	read := func(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
		data, tag, err := m.(*client).request(ctx, "GET", "/groups/"+pathID(d.Id()), "", nil)
		if err != nil {
			return missing(d, err)
		}
		return set(d, map[string]any{"name": data["name"], "etag": tag})
	}
	return resource(map[string]*schema.Schema{"name": text(true, true)}, read,
		func(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
			_, reviewed, err := m.(*client).request(ctx, "GET", "/groups", "", nil)
			if err != nil {
				return diag.FromErr(err)
			}
			data, _, err := m.(*client).request(ctx, "POST", "/groups", reviewed, map[string]any{"name": d.Get("name")})
			if err != nil {
				return diag.FromErr(err)
			}
			id, ok := data["id"].(string)
			if !ok {
				return diag.Errorf("Auth omitted group ID")
			}
			d.SetId(id)
			return read(ctx, d, m)
		}, nil, func(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
			_, _, err := m.(*client).request(ctx, "DELETE", "/groups/"+pathID(d.Id()), tagOf(d), nil)
			if err != nil {
				return diag.FromErr(err)
			}
			d.SetId("")
			return nil
		})
}

// Keep the app's complete reviewed editable configuration. Updating a subset
// must not reset fields which the API's full settings command would default.
var appFields = map[string]string{"name": "name", "entity_id": "entityId", "acs_url": "acsUrl", "acs_binding": "acsBinding", "name_id_format": "nameIdFormat", "name_id_source": "nameIdSource", "sign": "sign", "digest": "digest", "launch_url": "launchUrl", "slo_url": "sloUrl", "slo_binding": "sloBinding", "relay_state": "relayState", "idp_initiated": "idpInitiated"}

func appBody(d *schema.ResourceData) map[string]any {
	body := map[string]any{"protocol": "saml"}
	for key, api := range appFields {
		body[api] = d.Get(key)
	}
	return body
}
func app() *schema.Resource {
	fields := map[string]*schema.Schema{"name": text(true, false), "entity_id": text(true, false), "acs_url": text(true, false), "idp_initiated": {Type: schema.TypeBool, Optional: true, Default: false}}
	for _, key := range []string{"acs_binding", "name_id_format", "name_id_source", "sign", "digest", "launch_url", "slo_url", "slo_binding", "relay_state"} {
		fields[key] = &schema.Schema{Type: schema.TypeString, Optional: true, Default: ""}
	}
	fields["acs_binding"].Default = "post"
	fields["name_id_format"].Default = "persistent"
	fields["sign"].Default = "response"
	fields["digest"].Default = "sha256"
	fields["slo_binding"].Default = "redirect"
	read := func(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
		data, tag, err := m.(*client).request(ctx, "GET", "/apps/"+pathID(d.Id()), "", nil)
		if err != nil {
			return missing(d, err)
		}
		if data["protocol"] != "saml" {
			return diag.Errorf("only SAML apps can be imported")
		}
		// Refuse unsupported security settings rather than dropping them on apply.
		if data["encryption"] != nil || data["wantRequestsSigned"] == true || data["sha1Exception"] == true || lenList(data["attributes"]) > 0 {
			return diag.Errorf("app has settings outside this provider's supported SAML profile")
		}
		acs, ok := data["acs"].([]any)
		if !ok || len(acs) != 1 {
			return diag.Errorf("provider requires exactly one SAML assertion consumer")
		}
		first, ok := acs[0].(map[string]any)
		if !ok {
			return diag.Errorf("invalid SAML assertion consumer")
		}
		values := map[string]any{"etag": tag, "acs_url": first["url"], "acs_binding": first["binding"], "slo_url": "", "slo_binding": "redirect"}
		for key, api := range appFields {
			if key == "acs_url" || key == "acs_binding" || key == "slo_url" || key == "slo_binding" {
				continue
			}
			value := data[api]
			if value == nil {
				value = ""
			}
			values[key] = value
		}
		if slo, ok := data["slo"].(map[string]any); ok {
			values["slo_url"] = slo["url"]
			values["slo_binding"] = slo["binding"]
		}
		return set(d, values)
	}
	write := func(method string) schema.CreateContextFunc {
		return func(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
			path, tag := "/apps", ""
			body := appBody(d)
			if method == "PATCH" {
				d.Partial(true)
				path += "/" + pathID(d.Id())
				tag = tagOf(d)
				delete(body, "protocol")
			}
			if method == "POST" {
				_, reviewed, err := m.(*client).request(ctx, "GET", "/apps", "", nil)
				if err != nil {
					return diag.FromErr(err)
				}
				tag = reviewed
			}
			data, _, err := m.(*client).request(ctx, method, path, tag, body)
			if err != nil {
				return diag.FromErr(err)
			}
			if method == "POST" {
				id, ok := data["id"].(string)
				if !ok {
					return diag.Errorf("Auth omitted app ID")
				}
				d.SetId(id)
			}
			d.Partial(false)
			return read(ctx, d, m)
		}
	}
	return resource(fields, read, write("POST"), schema.UpdateContextFunc(write("PATCH")), func(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
		_, _, err := m.(*client).request(ctx, "DELETE", "/apps/"+pathID(d.Id()), tagOf(d), nil)
		if err != nil {
			return diag.FromErr(err)
		}
		d.SetId("")
		return nil
	})
}
func lenList(v any) int {
	if a, ok := v.([]any); ok {
		return len(a)
	}
	return 0
}
func assignmentParts(id string) ([]string, error) {
	parts := strings.Split(id, "/")
	if len(parts) != 3 || parts[0] == "" || parts[2] == "" || (parts[1] != "person" && parts[1] != "group") {
		return nil, fmt.Errorf("assignment import ID must contain app ID, person or group, and principal ID separated by slashes")
	}
	return parts, nil
}
func assignmentPath(parts []string) string {
	return "/assignments/" + pathID(parts[0]) + "/" + parts[1] + "/" + pathID(parts[2])
}
func findAssignment(ctx context.Context, c *client, parts []string) (map[string]any, string, error) {
	offset := 0
	firstTag := ""
	for {
		data, tag, err := c.request(ctx, "GET", fmt.Sprintf("/assignments?limit=100&offset=%d", offset), "", nil)
		if err != nil {
			return nil, "", err
		}
		if firstTag == "" {
			firstTag = tag
		} else if firstTag != tag {
			return nil, "", fmt.Errorf("Auth assignments changed during pagination; review a fresh plan")
		}
		items, ok := data["items"].([]any)
		if !ok {
			return nil, "", fmt.Errorf("invalid Auth assignment page")
		}
		for _, item := range items {
			row, ok := item.(map[string]any)
			if ok && row["appId"] == parts[0] && row["principalType"] == parts[1] && row["principalId"] == parts[2] {
				return row, tag, nil
			}
		}
		if data["nextOffset"] == nil {
			return nil, tag, nil
		}
		next, ok := data["nextOffset"].(float64)
		if !ok || int(next) <= offset {
			return nil, "", fmt.Errorf("invalid Auth pagination")
		}
		offset = int(next)
	}
}
func assignment() *schema.Resource {
	read := func(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
		parts, err := assignmentParts(d.Id())
		if err != nil {
			return diag.FromErr(err)
		}
		row, tag, err := findAssignment(ctx, m.(*client), parts)
		if err != nil {
			return diag.FromErr(err)
		}
		if row == nil {
			d.SetId("")
			return nil
		}
		role := row["role"]
		if role == nil {
			role = ""
		}
		return set(d, map[string]any{"app_id": parts[0], "principal_type": parts[1], "principal_id": parts[2], "role": role, "etag": tag})
	}
	write := func(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
		if d.Id() != "" {
			d.Partial(true)
		}
		parts := []string{d.Get("app_id").(string), d.Get("principal_type").(string), d.Get("principal_id").(string)}
		tag := tagOf(d)
		if d.Id() == "" {
			row, fresh, err := findAssignment(ctx, m.(*client), parts)
			if err != nil {
				return diag.FromErr(err)
			}
			if row != nil {
				return diag.Errorf("assignment already exists; import it before managing it")
			}
			tag = fresh
		}
		_, _, err := m.(*client).request(ctx, "PUT", assignmentPath(parts), tag, map[string]any{"role": d.Get("role")})
		if err != nil {
			return diag.FromErr(err)
		}
		d.SetId(strings.Join(parts, "/"))
		d.Partial(false)
		return read(ctx, d, m)
	}
	return resource(map[string]*schema.Schema{"app_id": text(true, true), "principal_type": {Type: schema.TypeString, Required: true, ForceNew: true, ValidateFunc: validation.StringInSlice([]string{"person", "group"}, false)}, "principal_id": text(true, true), "role": {Type: schema.TypeString, Optional: true, Default: ""}}, read, write, schema.UpdateContextFunc(write), func(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
		parts, err := assignmentParts(d.Id())
		if err != nil {
			return diag.FromErr(err)
		}
		_, _, err = m.(*client).request(ctx, "DELETE", assignmentPath(parts), tagOf(d), nil)
		if err != nil {
			return diag.FromErr(err)
		}
		d.SetId("")
		return nil
	})
}
