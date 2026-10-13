# Linking apps to Auth

Auth provides `oidc-provider@1`. An app that declares that optional dependency
(Base's `dependencies` module, for example Spool or Lamp) links to Auth by a
pull: Auth reads the app's own documents, and the app proves itself with a
link key that never leaves its server. Nothing in a request can choose where
Auth sends a code.

## What Auth serves

- `GET /.well-known/rer-provider`: `issuer`, `version: 1`, `interface` and
  `provides: ["oidc-provider@1"]`, and the absolute `initiate`, `redeem`,
  `deregister` and `report` URLs, all on the issuer.
- `GET /.well-known/rer-dependencies`: Auth's own graph node. It provides
  `oidc-provider@1` and depends on nothing.
- Discovery adds `end_session_endpoint`, `backchannel_logout_supported` and
  `backchannel_logout_session_supported`.

## Three ways to approve a link

1. **On the Apps page.** An administrator enters the app's address under "Add
   an app". Auth reads the app's `/.well-known/rer-dependencies` and link JWKS
   at that exact origin and lists the request, headlined by its origin. It flags
   punycode origins, origins Auth has never seen, a request that would
   replace an existing link with a new key, and every app the link would
   replace: one at another origin that holds the app's sector (its link moves
   here, with the identifiers people had there) or one at this origin with
   another sector (people's identifiers at this app change). The app's owner
   must also approve in the app, within ten minutes. "Approve app" re-reads the
   app and links only what was shown, and is refused if what it replaces
   changed since the request.
2. **With a link token, for `rer setup --non-interactive`.** "Create link token"
   returns, once, the JSON that `rer setup` reads from `RER_LINK_TOKEN_FILE`. It
   covers one exact origin and its callback set (the fixed link callback plus
   `/auth/oidc/auth/callback` and `/auth/oidc/auth/logout`), is single use and
   lasts an hour. Auth keeps only its digest.
3. **From an agent proposal.** A preparer key can file `approve_app_link` (target:
   the app's origin) or `remove_app_link`. A person approves with a passkey, as
   for the other kinds. The proposal names every app the link would replace,
   as on the Apps page, and goes stale if that changes.

Links made with a token or by RER are flagged on the Apps page, and every
administrator is emailed about them. A failed link is recorded in Activity with
the app's own symbolic reason.

## The handshake

Auth posts a one-use code, valid for 60 seconds, to the app's fixed
`/.well-known/rer-link/callback`. The app redeems it at `/oidc/link/redeem` with
an ES256 assertion signed by the link key Auth pulled. The assertion carries
`iss` and `sub` equal to the app's origin and `aud` equal to the redeem URL, and
lasts at most 60 seconds. Its `jti` is unique, and its `code`, `interface`,
`sector_id` and `callback` must match. Redemption is atomic: of concurrent
redemptions of one code, exactly one wins. Auth answers `initiate` only after
the app has accepted the callback.

**Continuity.** A client is found by the app's sector. It keeps its `client_id`
and sector for life. If the app signs with its unchanged key, the answer carries
`continuity: "previous-key"`. A new key counts only when an administrator
approved the request with the existing link shown (`"provider-owner"`). A token
or RER approval with a new key is refused (`link_continuity_required`). A link
that would replace an app its approval did not name is refused
(`replacement_not_approved`).

**Origins.** A production install refuses loopback and plain-http app origins.
A local (dev) install serves only loopback apps, and every token it issues
carries `amr: ["dev"]`.

## Versions in use

Apps report the interface version they run with `POST /oidc/link/report`
`{client_id, version, client_assertion}`, signed with their link key (`aud` is
the report URL). Linking records the version from the app's document too. Auth
keeps every version a live client reports. A report below the highest accepted
version is held (`409 downgrade_requires_owner`) until the owner accepts it on
the Apps page. A re-link whose document reports a lower version is held the same
way, unless the owner approved that link.

## Sign-out and fences

- **Sign out everywhere** (My account) ends every Auth session of that person.
  It also sends each app they used a signed `logout+jwt`: the back-channel
  event, the person's pairwise `sub`, a unique `jti` and no `nonce`.
- **Suspension** sends the `https://runeditrun.com/events/identity-fence` event,
  which ends the person's sessions and minted credentials in each app.
- **End session** (`/oidc/logout`, RP-initiated logout) ends this browser's Auth
  session. It tells the apps that received tokens in that session, with its
  `sid`. A valid `id_token_hint` for this browser's session ends it at once;
  anything else asks the person to confirm. A `post_logout_redirect_uri` must
  be registered for the client.

Each delivery keeps one `jti`. It is retried from the scheduled handler (every
five minutes, with backoff) for up to 24 hours. A 2xx or 409 answer means the
app has it.

## Removal

"Remove app" (or an approved `remove_app_link`) disables the client: Auth
issues it no more codes or tokens, and sends a back-channel logout for everyone
it had signed in, since no later sign-out or fence reaches it. Deliveries
queued before the removal still go. An app that unlinks itself calls
`/oidc/link/deregister`, signed with its key, and Auth disables the client.
Re-linking later with a new key needs an administrator's approval.

## Export and import

`rer export` first writes a **signed grant map** into the database, so the
archive carries it. The map lists every app sector with each person's pairwise
subject there, and the former subjects kept from move-in. It is signed with
Auth's ES256 key, so a later provider can verify it against this issuer's JWKS.

The archive carries people, emails, passkey public keys, clients, grants,
subjects, interface versions and the audit log. It leaves out sessions and
one-time state, signing keys, the pairwise key, recovery and preparer secrets,
move-in staging rows, link tokens, codes and requests, logout deliveries and
the RER keys an owner trusted. Withdrawn RER keys are carried, so a restored
install keeps them withdrawn.

`rer import` restores into an empty checkout. Before restoring, it refuses any
app origin the destination could not serve: a checkout configured as hosted
(`AUTH_LOCAL=false`) refuses loopback and plain-http apps, and a local one
refuses public origins. It also refuses an active `@dev.localhost` persona. A
restored install at the same host keeps every client, sector and pairwise
subject. Apps re-link with their unchanged keys (`previous-key`), and people
keep their bindings. The new install generates new signing keys, which apps
fetch on the next unknown `kid`.
