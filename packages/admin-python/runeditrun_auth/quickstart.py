"""Run with python -m runeditrun_auth.quickstart from an empty installed app."""
import os
from pathlib import Path
from . import AdminClient, AuthAdminError


def main():
    try:
        client = AdminClient(issuer=os.environ["AUTH_ISSUER"], client_id=os.environ["AUTH_CLIENT_ID"],
                             private_key=Path(os.environ["AUTH_PRIVATE_KEY_FILE"]).read_bytes(),
                             kid=os.environ.get("AUTH_KEY_ID"), scopes=["groups.read"])
        for page in client.pages("/groups"):
            for group in page["data"]["items"]:
                print(group["name"])
    except AuthAdminError as error:
        raise SystemExit("Auth: " + error.code) from None
    except (KeyError, OSError):
        raise SystemExit("Configure the issuer, service registration and private key file.") from None


if __name__ == "__main__":
    main()
