Auth has no passwords. People sign in with an email link or a passkey, and administrators always use a passkey.

## Email links

At `/signin` a person enters their email address and chooses **Email me a sign-in link**. The link works only in the browser that asked for it, once, for a short time. Opening it on another device does nothing.

An email-link session can use the apps a person is allowed into and manage their own account. It cannot administer Auth.

## Passkeys

A passkey lives in the person's device or password manager and signs in with a touch: fingerprint, face or device PIN. To register one, a person confirms their email in that browser first (**Sign-in methods**, **Confirm my email**), then chooses **Register a passkey**. To add a second passkey, sign in with the first.

Passkeys belong to the issuer host they were made on. Moving Auth to another host is a provider move: people register new passkeys and each app's owner approves the new link.

Every so often Auth asks a passkey user to confirm their email again; **Sign-in methods** says when.

## Changes that need a fresh email confirmation

Registering a passkey, completing or approving a recovery, and every administrator change (people, roles, domains and provider rules) also need an email confirmation in the same browser within the last ten minutes. If Auth asks, choose **Confirm my email** on **Sign-in methods**, open the link, then try again.

## Required providers

If your company signs in with Google, Microsoft or Okta, Auth can require that provider for your email domain. People at that domain then sign in with the provider before using Auth, so turning someone off at the provider also ends their access here. The owner is exempt. Set the rule under **Required providers** on People or Sign-in methods. Provider settings are private: see [Auth commands](/docs/commands).

## Lost passkey

On **My account**, **Request passkey recovery** starts a recovery. It waits 72 hours unless another administrator approves it sooner, and every active session is notified, so a stranger cannot take over quietly. When it is ready, **Complete recovery** replaces the account's passkeys and you register a new one.

If you are the only administrator and you lose your passkey, see [Backup and restore](/docs/backup-and-restore#locked-out).

## Your profile and connected providers

**My account** shows your profile. You can change the details your company lets you change, such as your name or a preference an administrator made editable. A detail your HR system or an administrator holds shows who holds it, and only they can change it.

If your administrator configured providers such as Google, Microsoft or Okta, **Connect** adds one to your account. Auth asks you to confirm your email in this browser, then to sign in with the provider. It refuses an address that belongs to another person and an identity already connected to someone, and **Disconnect** refuses to remove the last way you can sign in.

