Everyone who can sign in is on **People**: their name and role, their email, and whether they are active, invited or suspended.

## Invite a person

Choose **Invite person**, enter their name and email and send it. They receive an email link and sign in from it in their own browser; nobody can accept an invitation for them. Until then they show as **Invited**.

## Allow your company's domain

Instead of inviting everyone one by one, choose **Allow a domain** and enter your company's domain, such as `example.com`. Anyone with an address there can then request an account from the sign-in page and confirm it by email. Allowed domains are listed under **Allowed domains**.

## Onboard a worker

**Onboard worker** adds an employee, a contractor or a service identity with their work email, worker type, employment (W-2 or 1099), job title, department, location, manager, start and end dates and any custom attributes you defined. They get one invitation, and every group whose rule matches them is evaluated at once. An address that already belongs to someone is refused, never merged: a former worker's address asks you to rehire that person instead.

## Edit people, and what overrides what

**Edit** changes a person's name, email, state and values. Each value remembers its source: your own edit (an override), the HR system, the directory feed, or the employee. The highest wins in that order, and when sources disagree the person's row shows **Source conflict**, with the values side by side, until you accept a source's value. People keep one stable identifier through renames, transfers, email changes, suspension, termination and rehire; an email change ends their sessions until they prove the new address.

Sources identify people by their own id, bound once and never changed. The admin API `POST /api/auth/directory/source` takes `{source: "hr" | "directory", records: [{sourceId, personId?, email?, fields}]}`; a record whose id is new, even with a matching email, waits for you to say which person it is.

## Bulk edits

**Bulk edit** chooses people by state, worker type, department or location, then a change (department, location, title or state). **Preview** lists each person, what changes, the groups and apps they gain or lose, and what is refused. **Apply preview** applies exactly that preview; if the directory moved in between, it asks you to preview again.

## Groups and rules

A group is static (you add people) or follows a rule on directory values. Under **Groups and rules** every member shows why they are in: added by an administrator, or the rule condition they match. Removing someone a rule matches excludes them so the rule does not add them back. Groups have owners and show the apps and app roles assigned to them.

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
