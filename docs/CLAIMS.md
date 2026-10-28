<!-- Generated from CONTRACT.md by contract-docs. Edit CONTRACT.md, then regenerate. -->

# Auth homepage claims

A claim is done when every clause behind it is done, missing when every one is missing, and partial otherwise.

| # | Claim | Clauses | Status |
| --- | --- | --- | --- |
| 1 | Sign in with a touch. Passkeys and email links for your team, and one sign-in across the apps you link. | `AUTH-IDENTITY-001` partial; `AUTH-PROTOCOL-001` partial; `AUTH-LINK-001` partial | partial |
| 2 | Each person confirms their email once, then registers a passkey. Administrators always sign in with one. | `AUTH-IDENTITY-001` partial | partial |
| 3 | Approve an app and your team signs in to it with Auth. Sign out everywhere reaches every app you linked. | `AUTH-LINK-001` partial; `AUTH-LOGOUT-001` partial | partial |
| 4 | Invite people, allow your company’s domain and suspend access from one list. | `AUTH-DIRECTORY-001` partial; `AUTH-DOMAINS-001` partial | partial |
| 5 | Stage a user export from Google Workspace, Microsoft Entra, Auth0, Okta or JumpCloud, review it, then admit people as invitations. | `AUTH-MOVEIN-001` partial | partial |
| 6 | Free as in code, free as in cost. MIT licensed, nothing to pay. | `CMD-001` partial; `AUTH-OPS-001` partial | partial |
| 7 | Run Auth on your own computer. Your people, passkeys and apps stay in your installation, and export with you. | `AUTH-HOST-001` partial; `AUTH-TRANSFER-001` partial | partial |
| 8 | Passkey recovery: another administrator approves, or a notified 72-hour delay passes. | `AUTH-IDENTITY-001` partial; `AUTH-RECOVERY-002` partial | partial |
| 9 | Sign out everywhere: end every session in every linked app. | `AUTH-LOGOUT-001` partial | partial |
| 10 | Activity: every account and issuer event, recorded. | `AUTH-AUDIT-001` partial | partial |
| 11 | Required providers: require Google, Microsoft or Okta for a domain. | `AUTH-FEDERATION-001` partial; `AUTH-DOMAINS-001` partial | partial |
| 12 | Agent proposals: an agent prepares a change; a person approves it with a passkey under the held company policy. | `AUTH-ADMIN-001` partial | partial |
| 13 | Export and import: people, apps and a signed grant map move with you. | `AUTH-TRANSFER-001` partial | partial |
| 14 | Run Auth on your own computer, register a passkey and link your first app. Free and open source, MIT licensed. | `CMD-001` partial; `AUTH-IDENTITY-001` partial; `AUTH-LINK-001` partial | partial |

Claims: 14; 0 done, 14 partial, 0 missing.
