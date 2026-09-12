"""pnases — looped interactive CLI for pnasys-ses (run it yourself).

Menu: create entry / read entry / list entries / delete entry / exit.
Prompts for access key + encryption key (+ data / directory where needed).
"""
from __future__ import annotations

from pnasys_ses import SecureEncryptionService as SES


def _prompt(text: str) -> str:
    try:
        return input(text).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        raise SystemExit(0)


def main() -> None:
    print("pnases — PNASystems Secure Encryption Service CLI")
    print("-------------------------------------------------")
    while True:
        print("\n1) Create encrypted entry")
        print("2) Read/decrypt an entry")
        print("3) List entries")
        print("4) Delete an entry")
        print("5) Exit")
        choice = _prompt("> ")
        try:
            if choice == "1":
                data = _prompt("Data to encrypt: ")
                access = _prompt("Access key: ")
                enc = _prompt("Encryption key: ")
                directory = _prompt("Directory (empty = default): ") or None
                stem = SES.CreateEncryptedFile(data, access, enc, directory)
                print(f"Saved as {stem}.json")
            elif choice == "2":
                access = _prompt("Access key: ")
                enc = _prompt("Encryption key: ")
                directory = _prompt("Directory (empty = default): ") or None
                print("\nDecrypted value:")
                print(SES.DecryptEncryptedFile(access, enc, directory))
            elif choice == "3":
                directory = _prompt("Directory (empty = default): ") or None
                entries = SES.ListEntries(directory)
                print("\nStored entries:" if entries else "\nNo stored entries.")
                for e in entries:
                    print(" -", e)
            elif choice == "4":
                access = _prompt("Access key: ")
                directory = _prompt("Directory (empty = default): ") or None
                print("Deleted." if SES.DeleteEncryptedFile(access, directory) else "Not found.")
            elif choice == "5":
                print("Exiting.")
                break
            else:
                print("Invalid option. Try again.")
        except SystemExit:
            raise
        except Exception as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    main()
