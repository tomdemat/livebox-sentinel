"""Local account recovery, without starting Sentinel or touching .env.

Usage on the server:
    docker compose exec -it livebox-sentinel python tools/account_admin.py reset-password

The password is requested privately through the terminal, never through flags.
"""
import argparse
import getpass
import sys
import time
from pathlib import Path

# Run from the application folder or from tools/: the package sits one level up.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinel import main as app  # noqa: E402


def reset_owner_password(password):
    if not 12 <= len(password) <= 1024:
        raise ValueError("Le mot de passe doit contenir entre 12 et 1 024 caractères.")
    connection = app.connect_db()
    try:
        with connection:
            if not connection.execute("SELECT 1 FROM web_account WHERE id=1").fetchone():
                raise ValueError("Le compte doit d’abord être initialisé par l’application.")
            connection.execute(
                "UPDATE web_account SET password_hash=?, auth_version=auth_version+1, updated_at=? WHERE id=1",
                (app.hash_web_password(password), int(time.time())),
            )
            connection.execute("DELETE FROM web_sessions")
            connection.execute("DELETE FROM feature_documents WHERE kind IN ('totp','totp-pending') AND id='owner'")
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser(description="Récupération locale du compte propriétaire Livebox Sentinel")
    parser.add_argument("action", choices=["reset-password"])
    parser.parse_args()
    if not sys.stdin.isatty():
        parser.error("Un terminal interactif est requis. Utilisez docker compose exec -it.")
    password = getpass.getpass("Nouveau mot de passe (12 caractères minimum) : ")
    confirmation = getpass.getpass("Confirmez le nouveau mot de passe : ")
    if password != confirmation:
        parser.error("Les mots de passe ne correspondent pas.")
    try:
        reset_owner_password(password)
    except ValueError as error:
        parser.error(str(error))
    print("Mot de passe réinitialisé. Toutes les sessions ont été fermées et le second facteur du propriétaire est désactivé. L’identifiant est conservé.")


if __name__ == "__main__":
    main()
