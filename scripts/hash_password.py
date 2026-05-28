"""Generate a bcrypt hash for the admin password.

Usage:
    python scripts/hash_password.py "minha senha"

Or, with prompt (no echo):
    python scripts/hash_password.py

Cole o resultado em ADMIN_PASSWORD_HASH no Railway (ou no .env local).
"""
import getpass
import sys

import bcrypt


def main():
    if len(sys.argv) > 2:
        print("uso: python scripts/hash_password.py [senha]", file=sys.stderr)
        sys.exit(2)
    if len(sys.argv) == 2:
        password = sys.argv[1]
    else:
        password = getpass.getpass("senha: ")
        confirm = getpass.getpass("confirme: ")
        if password != confirm:
            print("senhas não coincidem", file=sys.stderr)
            sys.exit(1)
    if not password:
        print("senha vazia", file=sys.stderr)
        sys.exit(1)
    h = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))
    print(h.decode("utf-8"))


if __name__ == "__main__":
    main()
