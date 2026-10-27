An app you link lets your team sign in to it with Auth: one sign-in, and one place to end it. Apps link through the `oidc-provider@1` interface that compatible Run Edit Run apps declare.

## Add an app

1. Open **Apps** and enter the app's address under **Add an app**, then choose **Check app**.
2. Auth reads the app's own link documents at that exact address and lists it, headlined by its origin. It flags anything unusual: an address Auth has never seen, a look-alike (punycode) address, or a link that would replace one you already have.
3. Choose **Approve app**. The app's owner approves the link in the app too, within ten minutes.

The app then shows **Active**, with the interface version it reported.

## Link an app from its setup

When you set up an app with `rer setup`, it can link itself with a **link token**. On **Apps**, enter the app's address under **Link token for rer setup** and choose **Create link token**. Copy the token into a private file and give its path to the app's setup as `RER_LINK_TOKEN_FILE`. The token works once, for that one address, for an hour; Auth shows it only once.

## Sign out everywhere

On **My account**, **Sign out everywhere** ends all of your Auth sessions and signs you out of every app you linked. Suspending a person does the same for them.

## Remove an app

**Remove app** ends the link: the app can no longer sign anyone in through Auth. To bring it back, add it again.

## What apps learn about people

Auth shares each person's email and name with the apps they use, and nothing else. Each app sees its own identifier for a person, so apps cannot match people up between themselves.

For how linking works underneath, see [How app linking works](/docs/linking).

## Your company apps

On **My account**, search **Your apps** by name, save favorites, or choose **Recently used** for links you opened from the dashboard. Preferences belong to the signed-in person and employer. Saving a favorite never grants access.

A tile shows its assigned role or explains denied access, expired temporary access, an account waiting for provisioning, or a connector that needs administrator attention. Where an administrator configured requests, **Request access** selects the app in the existing temporary-access form. Its passkey approval and classification rules still apply.

When adding a native app, administrators can set its **App sign-in URL**. SAML apps can instead permit Auth-initiated sign-in. The launcher rechecks access before opening either address.

Administrators add **Group bookmarks** on **Company apps**, choosing a name, URL, icon and group. Only current group members see these links. They carry no Auth credential or protocol assertion. Removing membership hides the tile and refuses its saved launch address. Bookmarks do not control access to the external website itself.

Native SAML and OpenID Connect sign-in recheck the current assignment, including temporary-grant expiry, before issuing an assertion, code or token. A provisioning explanation describes the connector's observed state; it does not replace the app's own authorization checks. Password extension support, RER local linking and vendor qualification remain pending.
