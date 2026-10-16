Auth runs on your own computer with one command. This page takes you from nothing to a signed-in owner with a passkey.

## Install rer

`rer` is the Run Edit Run command. Install it once per computer:

```sh
curl -fsSL https://runeditrun.com/install.sh | sh
```

or `npm install -g @runeditrun/rer`. Auth needs Node 22 and pnpm 10.12.4, on macOS, Linux or Windows with WSL2.

## Get Auth and start it

```sh
git clone https://github.com/just-every/run-auth.git
cd run-auth && rer dev
```

The first `rer dev` installs everything, sets up a local database, makes you the owner and prints two lines:

- `RER_READY` is the address Auth answers on, `http://localhost:` and a port.
- `RER_OPEN` opens Auth in your browser, already signed in as you. It carries this checkout's private key, so open it only on this computer.

Auth listens on `localhost` rather than an IP address because browsers only allow passkeys on a named host. The address is your **issuer host**: apps you link remember it, so choose it before you link any.

## Finish setup

The first page you see is **Finish setup**. Check the name and email of the owner, tick **I confirm this owner account is ready to use.** and choose **Finish setup**. Auth opens My account.

## Register your passkey

A browser that opened through `RER_OPEN` can look around, but changing anything as an administrator needs a passkey.

1. Open **Sign-in methods** and choose **Confirm my email**. On your computer Auth sends no real mail: run `rer outbox` in the `run-auth` folder, open the link it prints and follow the newest sign-in message, in the same browser.
2. Back on **Sign-in methods**, choose **Register a passkey** and confirm with your fingerprint, face or device PIN.

From now on you sign in at `/signin` with **Continue with a passkey**. Next: [invite your team](/docs/people) and [link your first app](/docs/apps).

## Stop and start again

`rer dev --stop` stops Auth. `rer dev` starts it again with everything as you left it: people, passkeys and apps live in this folder.
