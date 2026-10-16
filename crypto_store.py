
import json
import sqlite3
from pathlib import Path
from cryptography.fernet import Fernet

KEY_FILE = Path.home() / ".config/sentinel-trap/fernet.key"
DB_FILE = Path.home() / "sentinel-trap" / "events.db"
LOG_FILE = Path.home() / "cowrie/var/log/cowrie/cowrie.json"


def store_events():
    if not KEY_FILE.exists():
        print("Encryption key not found.")
        return

    if not LOG_FILE.exists():
        print("Cowrie log not found:", LOG_FILE)
        return

    cipher = Fernet(KEY_FILE.read_bytes())
    DB_FILE.parent.mkdir(parents=True, exist_ok=True)

    with LOG_FILE.open("r", encoding="utf-8") as log:
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS encrypted_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_hash TEXT UNIQUE NOT NULL,
                    encrypted_data BLOB NOT NULL
                )
            """)

            stored = 0

            for line in log:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                event_hash = __import__("hashlib").sha256(
                    line.strip().encode("utf-8")
                ).hexdigest()

                encrypted = cipher.encrypt(
                    json.dumps(event).encode("utf-8")
                )

                cursor = conn.execute(
                    """INSERT OR IGNORE INTO encrypted_events
                       (event_hash, encrypted_data) VALUES (?, ?)""",
                    (event_hash, encrypted),
                )
                stored += cursor.rowcount

    print(f"New encrypted events stored: {stored}")


if __name__ == "__main__":
    store_events()


def load_decrypted_events():
    """Load and decrypt events from the encrypted SQLite database."""
    if not KEY_FILE.exists() or not DB_FILE.exists():
        return []

    cipher = Fernet(KEY_FILE.read_bytes())
    events = []

    with sqlite3.connect(DB_FILE) as conn:
        rows = conn.execute(
            "SELECT encrypted_data FROM encrypted_events ORDER BY id"
        ).fetchall()

    for (encrypted_data,) in rows:
        try:
            decrypted = cipher.decrypt(encrypted_data)
            events.append(json.loads(decrypted.decode("utf-8")))
        except (ValueError, json.JSONDecodeError):
            continue

    return events
