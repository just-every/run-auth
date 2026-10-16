Everything Auth knows lives in the folder you cloned: people, passkeys (their public halves), apps and history. Back it up by exporting it, and restore by importing into a fresh copy.

## Export

Stop Auth, then export:

```sh
rer dev --stop
rer export --output exports/auth.rer
```

The archive holds people and their emails, passkey public keys, linked apps, the identifiers each app knows people by, and history, with a signed map of which app may sign in whom. It leaves out sessions, private keys and secrets, so keep it private but know that it cannot sign anyone in by itself. The `exports/` folder is never published or served.

## Restore

Import into a fresh, empty copy of Auth, then start it on the same address (host and port) the old copy used:

```sh
git clone https://github.com/just-every/run-auth.git auth-restored
cd auth-restored
rer import --input ../run-auth/exports/auth.rer --yes
rer dev
```

Import checks the archive and restores it in one step, and refuses app addresses the new copy cannot serve. On the same address every linked app carries on with its existing link, and people keep signing in with their passkeys. The new copy makes new signing keys, which apps pick up by themselves.

## Start over

`rer reset --yes` deletes this copy's local data and private settings. Export first if you want to keep anything; reset leaves the `exports/` folder alone.

## Locked out

If the only administrator loses their passkey, a recovery token gets you back in on your own computer:

```sh
rer recovery --local
```

It saves a one-use token to `.rer/local/recovery-token` (readable only by you) and prints just that path. Signed in as the owner, redeem it as [Auth commands](/docs/commands) describes, then register a new passkey. A token only works on the computer where Auth runs; it never works over the network.

## Moving to another host

Changing the issuer host is a provider move, not a restore: passkeys are bound to the old host, so people register new ones and each app's owner approves the new link. Choose the host before you link apps, and keep it.
