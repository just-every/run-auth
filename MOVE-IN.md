# Moving people into Auth

This guide is for an owner whose people already sign in through Google Workspace, Microsoft Entra, Auth0, Okta or JumpCloud. It says what Auth can bring across from that provider, what it cannot, and the order that keeps you safe while you try it.

## First: should you move at all?

Keep your current provider if it already handles the applications, devices and offboarding you need. Auth is for a small business running a few compatible RER apps that wants one sign-in it runs itself, with permissions kept inside each app. It is not a replacement for a workforce identity suite.

**Do not move** if your business depends on any of these. Auth does not provide them, and an export cannot carry them:

- SAML sign-in for third-party apps (Auth only speaks OpenID Connect to compatible apps)
- SCIM provisioning, or role and group sync into apps
- device management, device trust or conditional access
- your provider's own policies, password rules or multi-factor settings

If any of those matter, keep your provider. You can still use it to sign in to RER apps (see step 1 below).

## What an export carries

Auth reads the user list your provider exports, stages it for your review, and lets you admit people as ordinary invitations. From each row it keeps only:

- email address
- display name
- disabled state at the provider, when the export states it
- the provider's id for that person (the "source id")
- one context label, such as a Google org unit or a department, shown for your review only

**Nothing else moves.** Not passwords or password hashes, not multi-factor factors or passkeys, not app roles or group permissions, not sessions, devices, SAML or SCIM applications, and not policy. Every person admitted from a file must open an email link in their own browser before they can sign in, exactly like someone you invite by hand. A matching email address is never treated as proof that the person owns it. Group and department labels never become permissions.

## Export routes, per provider

The routes and fields below were read on 11 October 2026 (fields re-checked on 13 October 2026). Providers change their consoles; if Auth refuses your file, it says why in plain words.

| Provider | How to export | What Auth reads | Not in the export, or not read |
|---|---|---|---|
| **Google Workspace** | Admin console, Directory, Users, Download users, as CSV or JSON. A Google Sheets download is read by saving the sheet as CSV. [Google: download a list of users](https://knowledge.workspace.google.com/admin/users/advanced/download-a-list-of-users?hl=en) | CSV: email, first and last name, org unit. JSON: id, primary email, name, suspended or archived, org unit. | The CSV's status column is not documented, so a CSV gives no disabled state and no source id. Use the JSON download if you want suspended people marked. |
| **Microsoft Entra** | Entra admin center, Users, All users, Download users, CSV. [Microsoft: download a list of users](https://learn.microsoft.com/en-us/entra/identity/users/users-bulk-download) | object id, mail (or user principal name when mail is empty), display name, account enabled, department. | Group membership, licences and app assignments. |
| **Auth0** | Management API bulk user export job, CSV or JSON (newline-delimited). Include at least `user_id`, `email`, `name` and `blocked`. [Auth0: bulk user exports](https://auth0.com/docs/manage-users/user-migration/bulk-user-exports) | user id, email, name, blocked. | Password hashes (ordinary exports omit them, and Auth uses no passwords anyway), factors, organizations, connections, callbacks. |
| **Okta** | Save the JSON response of the Users API list (`GET /api/v1/users`). There is no console file export. [Okta: Users API](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/User/) | id, status (suspended and deprovisioned count as disabled), profile email or login, names, department. | Group membership needs separate API calls and is not read. Factors and app assignments. |
| **JumpCloud** | Admin portal, Identity Management, Users, Export, All Data, as CSV or JSON (`jcuserlist_yyyymmdd`). [JumpCloud: users list](https://jumpcloud.com/support/admin-portal-users-list) | id, username, email, names, state or suspended, department. The export date is taken from the file name. | JumpCloud's page lists no columns; Auth reads JumpCloud's documented API field names. Check your first real file stages correctly. Devices and policies never move. |

The test fixtures that match these formats, and which columns could not be confirmed, are listed in [tests/fixtures/move-in/README.md](tests/fixtures/move-in/README.md).

## The order that keeps you safe

1. **Link one RER app and keep your provider as the directory.** Auth can send sign-in to Google, Microsoft or Okta through its upstream presets (the private `AUTH_UPSTREAM_PROVIDERS` setting described in [AUTH-COMMANDS.md](AUTH-COMMANDS.md)). You can also require that provider for your company's email domain, so offboarding at the provider still ends access. For Auth0 and JumpCloud there is no upstream sign-in route in Auth today; Auth has no generic OpenID upstream either. With those providers, step 1 is simply running Auth beside them for one app.
2. **Rehearse suspension and recovery while the old provider still works.** Suspend a test person on the People page and check the app refuses them. Run the local recovery token (`rer recovery --local`) and the delayed passkey recovery on My account, so you know how to get back in before anyone depends on Auth.
3. **Import people.** On People, choose **Move people in**, stage the export, and review it. Each row is marked new, already a person, a duplicate inside the file, disabled at source, on an email domain Auth refuses, or your own address. Disabled and duplicate rows start unselected. Admit the rows you want; nobody is emailed until you choose **Send invitations**. If you change your mind, **Undo this batch** removes the people it admitted who have not signed in, hold no passkey or app grant, and have no later activity. Everyone else stays, and the undo lists them with the reason. After an undo, staging the same file again starts a new batch. A CSV with more than 200 columns is refused before its rows are read; export the provider's standard user list.
4. **Keep the old provider until the last app has moved.** People sign in to Auth for the first time from their own email link. Leave the old provider running until every app you care about uses Auth and your recovery rehearsal has worked.

## Auth0 apps: the former subject map

Apps that used Auth0 know each person by Auth0's `user_id`. After admitting an Auth0 file, the review offers a CSV of each old `user_id` and the Auth email it was admitted as. Give it to an app's owner so they can rebind accounts deliberately. A former subject is only data: Auth never accepts a token carrying it, and apps receive Auth's own per-app subject, never the old one. Only admitted people are in the map; people you did not admit, or whom an undo removed, are not.

## Data you stage

Staged rows hold personal data from the export (names, addresses, provider ids) until the batch is admitted or undone, and they stay in Auth's database for the record. They are listed only on the move-in review. `rer export` leaves out staged rows, and the former subject map travels with the people it belongs to in the signed grant map ([LINKING.md](LINKING.md#export-and-import)).

## What this does not prove

The formats here were built from provider documentation and hand-written test files. No provider account was used. Before a live cutover, export one real file from your tenant, stage it, and check the review before admitting anyone.
