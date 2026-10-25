# Diagnose and repair sign-in

Diagnostics prepares a bounded repair for an owner to review. Applying a repair does not prove that an employee can sign in or log out; that requires the separate live protocol probe.

## Configure the server

Set `AUTH_AGENT_MODEL_KEY` as a server secret. Optionally set `AUTH_AGENT_MODEL_WORKSPACE`; the server sends it as the `anthropic-workspace-id` header. Never put either value in a proposal, browser form, documentation or log.

The provider is Anthropic and the fixed model is `claude-haiku-4-5-20251001`, called through the [Messages API](https://platform.claude.com/docs/en/api/messages/create). The model has no tools or execution authority. It receives only server-built, owner-approved redacted facts: configuration counts and matches, assignment and policy results, observed protocol events, change history, certificate dates and recovery mail outcomes. It never sees employee names, email addresses, credentials, authentication links or raw traces. The server validates citations and independently decides whether the evidence justifies a repair.

## Use Agents

1. Sign in as the owner with a passkey and confirm email in this browser within the last ten minutes. Open Agents at `/app/agents`. Have a current preparer key accountable to this owner; mint one under **Preparer keys** if needed. The diagnostic form selects the key record, not its raw secret.
2. Expand **Diagnose sign-in → Prepare a repair**. Select **Accountable agent key**, **Company app**, **Assigned test employee** and **Failure to investigate**. The employee must be active and assigned to the app.
3. Enter the relevant **Expected callback**, **Published replacement certificate ID** or **Pending recovery ID**. Approve the checkbox for sending this snapshot's redacted facts, then choose **Diagnose and prepare**. Consent to this snapshot does not approve the change.
4. Open the proposal. Review the explanation, test employee, exact before and after values, affected apps, next action and **Approved sources and citations**. Choose **Approve with passkey** to apply the exact repair, or **Reject**. Approval needs fresh email confirmation again and runs once only while its bound state still matches.

The UI labels a completed write **Repair applied**, while its diagnostic verification remains **Unverified**. Do not report working access from that status alone.

## Supported repairs

- **OIDC callback:** replaces the sole registered callback with the supplied expected URI. The URI must have no query string, differ from the registered URI and match the observed refused callback trace for this app and test employee. The diagnosis must cite both configuration and protocol evidence. Multiple registered callbacks do not qualify for this repair.
- **Expired SAML signing certificate:** activates the selected staged, published replacement only when the active certificate has expired and the replacement is currently valid. This changes signing for all SAML apps, not just the selected app; review the affected apps shown. The previous certificate remains published for rollback.
- **Failed recovery notice:** resends the plain notice to the same verified mailbox for a still-pending recovery with an observed failed mail outcome. It does not change factors, approve or complete recovery, or shorten the recovery delay.

Missing or conflicting evidence produces an uncertain diagnosis with a next diagnostic action and no approvable repair. Follow that action, gather the missing evidence and prepare again. A denied assignment or inactive employee cannot acquire access through diagnostics. Changed app, employee, assignment, certificate, policy or recovery state makes the approval scope stale; prepare a new diagnosis rather than reusing consent.

If the model is not configured, unavailable or returns invalid output, correct the server configuration or provider issue and prepare again. These failures do not establish a repair or successful access.

## Verify with a scoped employee session

Run `node ./scripts/diagnostic-probe.mjs` from the repository root, outside the model. Obtain explicit consent from the selected test employee to use and end this session. Supply values through the operator process environment; never paste credentials into model context, proposals, documentation or logs.

Common environment variables:

| Variable | Purpose |
| --- | --- |
| `AUTH_ORIGIN` | Auth issuer origin |
| `AUTH_PROPOSAL_ID` | The exact approved sign-in repair proposal |
| `AUTH_PREPARER_KEY` | Its accountable preparer key, accepted only by the preparer API |
| `AUTH_TEST_SESSION` | The consenting test employee's signed-in session cookie |
| `AUTH_PROBE_CONSENT` | Must equal `end-test-session` |

The command reads only that key's own approved effect. It takes the employee, app and protocol target from the effect; caller parameters and model prose cannot substitute a different employee or app. Pending, rejected, failed and unrelated proposals cannot run a probe.

For an OIDC client using a secret, supply `AUTH_PROBE_CLIENT_SECRET`; the bounded consumer supports public clients, basic client secrets and posted client secrets. For SAML, supply the test service provider's `AUTH_PROBE_SP_PRIVATE_KEY`. Its public certificate, endpoints and signing requirements come from the approved effect. Unsupported profiles remain unverified and need the app owner's existing consumer.

The implementation in ./scripts/agents/probe.mjs checks the session's employee ID before exercising the protocol. OIDC verifies the authorization code flow, user information and logout, then checks that both the access token and employee session are refused. SAML validates the signed response against currently valid published certificates, validates the correlated logout response and checks that the employee session is refused.

Only successful live execution prints `signIn: verified` and `logout: verified` with the test identity, proposal and app IDs. Failure exits unsuccessfully with a credential-free message and leaves the repair unverified. Inspect the employee journey and follow the proposal's next action; obtain a new consented session before another probe if logout already ended it. A protocol probe does not by itself prove delivery of a recovery notice: inspect the observed mail outcome separately.
