"""
One-off helper to (re)create backend/data/system_users.db with hashed
passwords. Run with: python backend/data/seed_users.py

Edit the USERS list below before running, or import create_user()/init_db()
from backend.auth directly to add users from a script/shell.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from auth import init_db, create_user, DB_PATH

USERS = [
    # (username, password, role)
    ("alice_s", "s1234567", "SOC"),
    ("bob_a", "a1234567", "ADMIN"),
]

if __name__ == "__main__":
    init_db()
    for username, password, role in USERS:
        try:
            create_user(username, password, role)
            print(f"created {username} ({role})")
        except Exception as e:
            print(f"skipped {username}: {e}")
    print(f"db at {DB_PATH}")
