# Verified employer domains

An Auth owner or administrator starts an ownership challenge on Sign-in methods. The browser must have hardware passkey authority and an Auth email confirmation from the last ten minutes. The same authority is checked again when the write commits.

Each exact domain has a separate TXT challenge. Its name and value appear on the page, with a thirty-minute deadline. Auth reads that exact name through a fixed public DNS resolver. Incorrect, expired and used challenges fail. A unique installation-wide claim prevents a second employer from taking the domain, including after revocation. The response never identifies the other employer. Explicit invitations remain independent of another employer's domain claim.

After verification, the administrator can allow enrollment or require a configured provider. People at an alias or subdomain need their own domain proof and rule; no wildcard is inferred. The preview lists the existing affected people. Ownership supplies no individual email proof, passkey, upstream identity binding or account linking authority.

The existing human, scoped administrator, machine administration and approved preparer rule doors all require ownership. Database guards also protect the final enrollment and provider-rule writes. Existing unverified domain rules fail closed until an administrator proves ownership.

Revocation immediately reevaluates affected people at session, enrollment and federation policy checks. Non-owner access stays denied until reverification. Emergency owners keep the existing exemption; using it after revocation records `domain_emergency_access` in Activity. Revocation records affected people and emergency owners. An authorized owner can create a fresh challenge and restore the policy without changing the issuer, people or their credentials.

AUTH-ENROLLMENT-001 and future discovery or federation doors inherit the ownership gate before activating domain-based behavior. AUTH-PROFILE-001 retains its separate individual identity and account-linking proof.
