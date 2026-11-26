# Changelog

## 0.1.1 (26 Nov 2026)

Auth's first release since 0.1.0 (13 Oct 2026). Existing issuer, passkey and employer boundaries stay in force, and every shipped migration is unchanged; the new ones are additive.

- Mail off: an installation can run with `MAIL_PROVIDER=none`. Every send is refused with `mail_off`, sign-in mail requests answer 503 `mail_off`, and no sender or mail key is required. The owner signs in with a one-time `rer signin` link (migration 0081 adds the table it writes), which opens only the owner's session; other people need mail on to sign in.
- Runs on rer 0.2.134: `rer export` and the continuity drill run to the end again, and a refused send is no longer journalled as an uncertain delivery or counted against mail limits.
- Workforce identity: native factor custody with sensitive-app assurance and MFA recovery, SCIM source freshness with retained stop reasons, scoped administrator grant notices, audited paginated activity export, and federation certificate rotation.
- The shared agent door is adopted for the declared core, with group tools limited to internal access changes and customer-sourced results marked untrusted. The agent guide is generated on both public sites and checked against production listings.
- Signed-in app: an open session goes from / and /signin into the app, unknown routes answer inside the app frame, the profile saves as it changes, the owner sits at the foot of the menu with Sign out and Sign out everywhere, and phone tap targets reach 44 px.
