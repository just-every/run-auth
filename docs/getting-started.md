Auth runs on your own computer with one command. This page takes you from nothing to a signed-in owner with a passkey.

These guides are also published at https://run-auth.com/docs, and the run page is at https://run-auth.com/run.

The pages on https://run-auth.com are built from this repository's `docs/` folder and `src/site/`, so a fix to these guides goes live with the next change merged to `main`.

## Get Auth and start it

```sh
curl -fsSL https://runeditrun.com/install.sh | sh
rer dev just-every/run-auth
```

The first line installs `rer` for you alone, with its own Node if you have none. It changes no shell settings: if it prints an `export PATH=…` line, run that line before the second. Already have Node 22 or later? `npx -y @runeditrun/rer dev just-every/run-auth` does both lines in one.

The two lines install `rer`, the Run Edit Run command, clone Auth into `run-auth`, install everything and start it. Auth runs on macOS, Linux or Windows with WSL2, with git; the installer brings Node when it is missing, and rer brings pnpm. To start it again later, run `cd run-auth && rer dev`.

The first start installs everything, sets up a local database, makes you the owner and prints two lines:

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
