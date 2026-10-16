Everyone who can sign in is on **People**: their name and role, their email, and whether they are active, invited or suspended.

## Invite a person

Choose **Invite person**, enter their name and email and send it. They receive an email link and sign in from it in their own browser; nobody can accept an invitation for them. Until then they show as **Invited**.

## Allow your company's domain

Instead of inviting everyone one by one, choose **Allow a domain** and enter your company's domain, such as `example.com`. Anyone with an address there can then request an account from the sign-in page and confirm it by email. Allowed domains are listed under **Allowed domains**.

## Roles

There are three roles:

- **Owner**: the person who set Auth up. There is exactly one, and it cannot be suspended.
- **Administrator**: manages people, apps and settings, always with a passkey.
- **Member**: signs in to the apps they are allowed into and manages their own account.

The owner changes a role with **Update role** on the person's row.

## Suspend someone

**Suspend** ends a person's access at once: their Auth sessions end and every app you linked is told to sign them out. Suspended people stay on the list, so you keep their history.

## Everyone at once

Moving from Google Workspace, Microsoft Entra, Auth0, Okta or JumpCloud? **Move people in** stages your provider's user export so you can review and admit people as invitations. See [Move people in](/docs/move-in).
