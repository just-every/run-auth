# Changelog

## 0.1.2 (26 Nov 2026)

The hosted demo. No migrations; an installation's sign-in is unchanged.

- Each published release deploys demo.run-auth.com at its tag (`.github/workflows/run-demo.yml`), with mail off. A dispatch with `test_only` deploys the test host demo.test.run-auth.com.
- A demo visitor's copy opens on My account, signed in as its owner. In the demo only, the signed owner claim also proves the owner's email, completes first run and opens the owner's Auth session; on an installation the claim still opens only the operator session.
- The owner claim's audience defaults to the installation's own origin when `RER_OWNER_CLAIM_APP_ORIGIN` is unset, so a claim without it no longer fails with "Incomplete agent door trust". A value that is set must still equal `AUTH_ORIGIN`.

## 0.1.1 (26 Nov 2026)

Auth's first release since 0.1.0 (13 Oct 2026). Existing issuer, passkey and employer boundaries stay in force, and every shipped migration is unchanged; the new ones are additive.

- Mail off: an installation can run with `MAIL_PROVIDER=none`. Every send is refused with `mail_off`, sign-in mail requests answer 503 `mail_off`, and no sender or mail key is required. The owner signs in with a one-time `rer signin` link (migration 0081 adds the table it writes), which opens only the owner's session; other people need mail on to sign in.
- Runs on rer 0.2.134: `rer export` and the continuity drill run to the end again, and a refused send is no longer journalled as an uncertain delivery or counted against mail limits.
- Workforce identity: native factor custody with sensitive-app assurance and MFA recovery, SCIM source freshness with retained stop reasons, scoped administrator grant notices, audited paginated activity export, and federation certificate rotation.
- The shared agent door is adopted for the declared core, with group tools limited to internal access changes and customer-sourced results marked untrusted. The agent guide is generated on both public sites and checked against production listings.
- Signed-in app: an open session goes from / and /signin into the app, unknown routes answer inside the app frame, the profile saves as it changes, the owner sits at the foot of the menu with Sign out and Sign out everywhere, and phone tap targets reach 44 px.
