# Move-in fixtures

Every file here was written by hand from the column and field names that provider documentation publishes. No provider account was used and no live call was made. The people, addresses and identifiers are invented.

The export routes were read on 11 October 2026 for the market research. The column and field names below were re-read from the same pages, plus the provider's API reference where the export page names no fields, on 13 October 2026.

| File | Source and format | Documentation |
|---|---|---|
| `google-users.csv` | Google Workspace, Admin console "Download User Info In CSV File" | [Download a list of users](https://knowledge.workspace.google.com/admin/users/advanced/download-a-list-of-users?hl=en) (routes: CSV, JSON, Google Sheets); [Add or update multiple users from a CSV file](https://knowledge.workspace.google.com/admin/users/add-or-update-multiple-users-from-a-csv-file) (column names) |
| `google-users.json`, `google-30.json` | Google Workspace, JSON download | Download page above (route); [Directory API user resource](https://developers.google.com/workspace/admin/directory/reference/rest/v1/users) (field names) |
| `entra-users.csv`, `hostile-entra.csv` | Microsoft Entra, "Download users" CSV | [Download a list of users](https://learn.microsoft.com/en-us/entra/identity/users/users-bulk-download) |
| `auth0-users.csv`, `auth0-users.ndjson` | Auth0 bulk user export, CSV and NDJSON | [Bulk user exports](https://auth0.com/docs/manage-users/user-migration/bulk-user-exports) (formats, CSV escaping); [User profile structure](https://auth0.com/docs/manage-users/user-accounts/user-profiles/user-profile-structure) (field names) |
| `okta-users.json` | Okta, saved response of `GET /api/v1/users` | [Okta Users API](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/User/) (User object, `UserStatus` values, listUsers examples) |
| `jcuserlist_20261011.csv`, `jcuserlist_20261011.json` | JumpCloud admin portal user list export | [Users list](https://jumpcloud.com/support/admin-portal-users-list) (route and `jcuserlist_yyyymmdd` file name); [JumpCloud API v1 systemuser](https://docs.jumpcloud.com/api/1.0/index.html) (field names) |

Auth reads only these fields: source id, email, display name (or given and family names), disabled state and one context label (Google org unit; Entra, Okta or JumpCloud department). Group and department labels are shown as context and never become permissions.

## Confirmed, unconfirmed and absent

- **Google CSV.** Confirmed: `First Name [Required]`, `Last Name [Required]`, `Email Address [Required]`, `Org Unit Path [Required]`. **Not confirmed:** `Status [READ ONLY]` (present in the fixture, ignored by Auth). A Google CSV therefore carries no disabled state and no source id; both are absent. The page does not say the download uses exactly the upload headings; it says to download user info to edit and upload it again.
- **Google JSON.** The download page names no fields. Auth reads the Directory API user resource fields `id`, `primaryEmail`, `name.fullName`/`givenName`/`familyName`, `suspended`, `archived` and `orgUnitPath`, as a bare array or a `users` array. **Not confirmed:** that the console's JSON download uses that resource shape. Google Sheets output is read by downloading the sheet as CSV.
- **Microsoft Entra CSV.** Confirmed: `userPrincipalName`, `displayName`, `surname`, `mail`, `givenName`, `objectId`, `department`, `accountEnabled`. Email is `mail`, or `userPrincipalName` when `mail` is empty. Group membership is not in the download and is absent.
- **Auth0.** Confirmed: CSV strings carry a leading single quote, which Auth removes; JSON exports are newline-delimited. Field names `user_id`, `email`, `name`, `given_name`, `family_name`, `blocked` come from the user profile structure page. An export only contains the fields the job requested, so a missing `blocked` is absent, not false. No password hashes or factors are read; ordinary exports do not contain them. Auth0 has no groups in the profile; absent.
- **Okta.** Confirmed from the Users API: `id`, `status` (`SUSPENDED` and `DEPROVISIONED` count as disabled), `profile.email`, `profile.login`, `profile.firstName`, `profile.lastName`, `profile.displayName`, `profile.department`. Group membership needs a separate API call per group or user, so a user list carries no groups; absent.
- **JumpCloud.** The portal page confirms the export route and file name only. **Not confirmed:** every column of the CSV and the shape of the JSON. Auth reads JumpCloud's documented systemuser API field names (`_id`, `username`, `email`, `firstname`, `lastname`, `displayname`, `state`, `suspended`, `department`) and a bare array or `{totalCount, results}`. A real portal file with other headings is refused with a plain message; check one real export before relying on this route.

## Hostile input

`hostile-entra.csv` holds cells beginning with `=`, `+`, `-` and `@`, a row without a valid email, mixed-case and plus-addressed duplicates, and a lookalike Cyrillic `о` in a domain. The flow test also builds a file just over the 1 MB cap. `google-30.json` is the 30-row mixed batch used by the browser journey and the owner-effort count.
