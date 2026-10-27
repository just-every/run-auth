# Auth Terraform provider (local preview)

This source-built provider works with Terraform and OpenTofu. It currently manages
static groups, basic SAML apps and person or group app assignments through Auth's
version 1 Admin API. Public Registry publication and release signing are pending.
People, group rules, OIDC and password apps, attribute mappings, conditional-access
policies, identity providers, domains and automations remain future resources.
The Admin API's exact-domain provider requirement is not a conditional-access policy.

## Install locally

Use Go 1.24 or newer. From this directory, build into a filesystem mirror:

```sh
platform="$(go env GOOS)_$(go env GOARCH)"
mirror="$HOME/.local/share/auth-provider-mirror"
for registry in registry.terraform.io registry.opentofu.org; do
  destination="$mirror/$registry/runeditrun/auth/0.1.0/$platform"
  mkdir -p "$destination"
  go build -o "$destination/terraform-provider-auth_v0.1.0" .
done
```

Create a CLI configuration file, replacing the path with your absolute mirror path:

```hcl
provider_installation {
  filesystem_mirror {
    path = "/absolute/path/to/auth-provider-mirror"
  }
}
```

Set `TF_CLI_CONFIG_FILE` to that file for either CLI. This configuration installs
only from the local mirror. It makes no Registry availability claim.

An Auth administrator registers a service app on Agents with a public P-256 or
RSA key, accountable owner, expiry, purpose, scopes and resource restrictions.
Use `groups.manage`, `apps.manage` and `assignments.manage` for the example below.
Creation requires an unrestricted grant for the new resource kind. Existing IDs
can be narrowed separately. These are the existing Admin API authority rules;
the provider adds no authority. See [the Admin API guide](../../docs/admin-api.md).

Provide these environment variables outside HCL:

- `AUTH_ISSUER`: the Auth HTTPS origin; loopback HTTP is accepted for local installs.
- `AUTH_CLIENT_ID`: the service app client ID.
- `AUTH_PRIVATE_KEY_FILE`: a PKCS8 PEM RSA or P-256 private key file, kept outside the working directory with restrictive permissions.
- `AUTH_KEY_ID`: the registered JWK key ID.
- `AUTH_SCOPES`: optional space-separated subset of the service app's scopes.

The provider exchanges a fresh signed assertion for a short-lived token and
rechecks current Auth authority on every REST call. Private key contents and tokens
have no provider or resource schema fields and never enter state. Diagnostics omit
transport details and raw response bodies; redirects are refused. Protect Terraform
state and saved plans, which contain ordinary group, app and assignment configuration.
Do not enable external HTTP tracing around credential exchanges.

## Configure resources

For OpenTofu, use `registry.opentofu.org` in the fully qualified provider source.

```hcl
terraform {
  required_providers {
    auth = {
      source  = "registry.terraform.io/runeditrun/auth"
      version = "0.1.0"
    }
  }
}

provider "auth" {}

resource "auth_group" "engineering" {
  name = "Engineering"
}

resource "auth_saml_app" "payroll" {
  name      = "Payroll"
  entity_id = "https://payroll.example.com/saml"
  acs_url   = "https://payroll.example.com/acs"
}

resource "auth_assignment" "payroll" {
  app_id         = auth_saml_app.payroll.id
  principal_type = "group"
  principal_id   = auth_group.engineering.id
  role           = "employee"
}
```

Run `terraform init`, `terraform plan -out=reviewed.plan`, then
`terraform apply reviewed.plan`; the same commands work with `tofu`.
A second unchanged plan exits zero with `-detailed-exitcode`. UI changes are read
on the next plan. An app removed in the UI is planned for creation again; review
that effect before applying. Terraform may finish independent resources before
another resource fails: refusal is atomic per Auth resource, not across a whole plan.

| Resource | Fields | Update and import |
| --- | --- | --- |
| `auth_group` | Required `name` | A name change replaces the group, because the API has no rename command. Import by existing group ID. Groups with rules refuse import or refresh because this preview manages static groups only. Deletion uses the reviewed ETag and Auth checks every affected member and assignment. |
| `auth_saml_app` | Required `name`, `entity_id`, `acs_url`; optional `acs_binding` (post), `name_id_format` (persistent), `name_id_source` (empty), `sign` (response), `digest` (sha256), `launch_url`, `slo_url`, `slo_binding` (redirect), `relay_state`, `idp_initiated` (false) | Updates use PATCH with the exact reviewed tag. Import by existing app ID. Only one ACS and apps without attribute lists, encryption, required signed requests or SHA1 exceptions are supported; other profiles refuse import or refresh rather than resetting those settings. Stored service-provider certificates are preserved by machine updates when omitted. Delete disables the app. |
| `auth_assignment` | Required `app_id`, `principal_type` (person or group), `principal_id`; optional app `role` | Changing the target replaces the assignment. Role changes use the reviewed tag. Import ID is the app ID, principal type and principal ID joined by slashes. Paginated reads find the exact tuple; creation refuses an existing assignment until imported. |

All resources expose a computed `id` and `etag`. Never configure `etag` yourself.
Auth's strong ETag covers a shared administration revision. A saved plan that
loses that revision fails with 412, sends no automatic retry and preserves the
previous provider state. Reread and review a new plan before applying again.
The provider serializes its own HTTP calls and carries forward only revisions
from its own successful writes, allowing dependent resources in one apply.
An unrelated human edit can conservatively invalidate any pending mutation.

## Development checks

```sh
go test ./...
```

From the repository root, install actual CLI binaries with
`python3 scripts/install-terraform-tools.py /absolute/tools-directory`, put that
directory and Go on PATH, then run `pnpm test:terraform`. Both CLI journeys use a
fresh native Auth runtime, real D1 persistence and real private-key OAuth. The
existing company-app browser journey additionally creates resources with Terraform,
shows them at desktop and phone widths and detects an app removal through the UI.
These journeys run in branch Verify. They do not qualify a public release or the
unimplemented resource families.
