# Auth implementation claims

Generated from CONTRACT.md. Acceptance journeys remain in ACCEPTANCE.md.

Done: 38; partial: 36; missing: 18; total: 92.

| Clause | Title | Status |
| --- | --- | --- |
| AUTH-HOST-001 | Issuer host | done |
| AUTH-PRIVACY-001 | Shared claims | done |
| AUTH-RER-TRUST-001 | RER trust | done |
| AUTH-IDENTITY-001 | Owner and sign-in proof | done |
| AUTH-PROTOCOL-001 | OpenID Connect profile | done |
| AUTH-BOUNDARY-001 | Private authorization | done |
| AUTH-MOVEIN-001 | Staged move-in | done |
| AUTH-ADMIN-001 | Agent preparation | done |
| CMD-001 | Commands | done |
| HTTP-001 | HTTP surfaces | done |
| AUTH-LINK-001 | App links | done |
| AUTH-LOGOUT-001 | Sign-out reach | done |
| AUTH-TRANSFER-001 | Export and import | done |
| AUTH-DIRECTORY-001 | One workforce directory | done |
| AUTH-TENANCY-001 | Organizations and delegated administration | done |
| AUTH-TENANCY-002 | No cross-organization linking or proof transfer | done |
| AUTH-ROLES-001 | Custom administrator roles and resource sets | done |
| AUTH-DOMAINS-001 | Verified employer domains | done |
| AUTH-PROFILE-001 | Profiles and safe identity linking | done |
| AUTH-ENROLLMENT-001 | Managed enrollment and password compatibility | partial |
| AUTH-PASSWORD-001 | Password policy per group | missing |
| AUTH-PASSWORD-002 | Self-service password reset, unlock and propagation | missing |
| AUTH-ONBOARD-001 | New-hire activation before the start date | partial |
| AUTH-TAP-001 | Temporary access pass | partial |
| AUTH-EXPERIENCE-001 | Hosted and embedded identity journeys | partial |
| AUTH-LOCALE-001 | End-user display languages | missing |
| AUTH-LAUNCHER-001 | Employee app launcher | partial |
| AUTH-SWA-001 | Password-based app sign-in | missing |
| AUTH-MFA-001 | Passkey-first multifactor policy | partial |
| AUTH-AUTHENTICATOR-001 | Push authenticator in the Auth mobile app | missing |
| AUTH-POLICY-001 | Conditional access and session policy | partial |
| AUTH-ABUSE-001 | Automated attack protection | partial |
| AUTH-RISK-001 | Named sign-in behavior signals | missing |
| AUTH-NOTIFY-001 | Employee security notifications and suspicious-activity reports | partial |
| AUTH-LOGOUT-002 | Universal logout from connected SaaS for a compromised account | partial |
| AUTH-SAML-001 | SAML 2.0 workforce identity provider | done |
| AUTH-OIDC-001 | General SaaS OIDC and OAuth profiles | done |
| AUTH-MAPPING-001 | Attribute and NameID transform language | done |
| AUTH-CATALOG-001 | Production SaaS application catalog | partial |
| AUTH-CATALOG-002 | Catalog breadth and verification cadence | missing |
| AUTH-M365-001 | Microsoft 365 domain federation and licensing | missing |
| AUTH-SCIM-001 | Outbound provisioning and deprovisioning | done |
| AUTH-SCIM-002 | Inbound directory synchronization | partial |
| AUTH-HRIS-001 | HR-driven identity sources | missing |
| AUTH-HRIS-002 | Scheduled HR file feeds | done |
| AUTH-LIFECYCLE-001 | Complete joiner, mover and leaver execution | partial |
| AUTH-TIMING-001 | Measured lifecycle time bounds | partial |
| AUTH-WORKFLOWS-001 | Employer-built identity automations | missing |
| AUTH-FEDERATION-001 | Generic upstream federation | partial |
| AUTH-SOCIAL-001 | Controlled external identity sign-in | partial |
| AUTH-LEGACY-001 | LDAP, Active Directory and RADIUS access | missing |
| AUTH-DEVICE-001 | Device identity and trust | missing |
| AUTH-DESKTOP-001 | Sign in to the computer with company identity | missing |
| AUTH-GATEWAY-001 | On-premises web apps through an access gateway | missing |
| AUTH-PRIVILEGED-001 | Server and SSH access without standing keys | missing |
| AUTH-GRANTS-001 | App roles, APIs and service identities | done |
| AUTH-TOKENS-001 | Refresh and delegated session lifecycle | done |
| AUTH-HOOKS-001 | Inline hooks for custom sign-in logic | done |
| AUTH-REQUESTS-001 | Access requests and time-bound grants | partial |
| AUTH-REVIEWS-001 | Periodic access certification | partial |
| AUTH-DECISIONS-001 | Proof levels for administration and everyday decisions | partial |
| AUTH-CHAT-001 | Approve, deny and certify from Slack and Microsoft Teams | missing |
| AUTH-AUDIT-001 | Identity investigation and reporting | partial |
| AUTH-REPORTS-001 | Named per-person identity reports | partial |
| AUTH-COMPLIANCE-001 | Identity-provider connectors for compliance platforms | missing |
| AUTH-MIGRATION-001 | Switch from Okta, Entra ID or JumpCloud | partial |
| AUTH-MIGRATION-002 | Custom-directory and progressive move-in | done |
| AUTH-MIGRATION-003 | Cutover enrollment campaign | partial |
| AUTH-DEVELOPER-001 | Working integration SDKs and admin API | partial |
| AUTH-ADMINAPI-001 | Admin API credentials for automation | done |
| AUTH-TERRAFORM-001 | Terraform provider | partial |
| AUTH-MOBILE-001 | Native employee and administrator access | partial |
| AUTH-EVENTS-001 | Reliable lifecycle events and webhooks | done |
| AUTH-FOLLOWUP-001 | Follow-through until access is resolved | done |
| AUTH-FOLLOWUP-002 | Role-derived recipients, manage-follow-up authority and early send | done |
| AUTH-FOLLOWUP-003 | Access-request, review and stale-source obligations | done |
| AUTH-FOLLOWUP-004 | Slack, Teams and Oncall follow-up channels | missing |
| AUTH-DELIVERY-001 | Email and SMS delivery operations | partial |
| AUTH-OPS-001 | Operate a company identity service | partial |
| AUTH-RECOVERY-002 | Emergency continuity and recovery drills | done |
| AUTH-RECOVERY-003 | Same-day help-desk recovery for employees | partial |
| AUTH-ERASURE-001 | Authorized erasure with retained accountability | done |
| AUTH-ERASURE-002 | Per-person erasure across separate organization identities | partial |
| AUTH-ERASURE-003 | Erasure revokes everything | partial |
| AUTH-RETENTION-001 | Explicit retention and secret custody | partial |
| AUTH-TRANSFER-002 | Complete workforce portability | partial |
| AUTH-AGENT-001 | Agent-led SaaS onboarding | partial |
| AUTH-AGENT-002 | Diagnose and repair broken sign-in | done |
| AUTH-AGENT-003 | Find orphaned and excessive access | partial |
| AUTH-AGENT-004 | Person-bound delegated agent identities | done |
| AUTH-AGENT-005 | Verify revocation everywhere | partial |
| AUTH-AGENT-006 | External and MCP delegated task identities | done |
