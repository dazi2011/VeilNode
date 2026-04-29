from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from .errors import VeilDecryptError


def seen_db_path(home: str | Path | None = None, db_path: str | Path | None = None) -> Path:
    if db_path:
        return Path(db_path).expanduser()
    root = Path(home).expanduser() if home else Path.home() / ".veil"
    return root / "state" / "msg_seen.db"


def ensure_seen_db(path: str | Path) -> None:
    db = Path(path)
    db.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS seen_messages (
                msg_id TEXT PRIMARY KEY,
                receiver_id TEXT,
                root_fingerprint TEXT,
                root_epoch INTEGER,
                file_hash TEXT,
                seen_at INTEGER,
                message_fingerprint TEXT
            )
            """
        )


def list_seen(path: str | Path) -> dict:
    ensure_seen_db(path)
    with sqlite3.connect(path) as conn:
        rows = conn.execute(
            """
            SELECT msg_id, receiver_id, root_fingerprint, root_epoch, file_hash, seen_at, message_fingerprint
            FROM seen_messages
            ORDER BY seen_at DESC
            """
        ).fetchall()
    return {
        "database": str(path),
        "messages": [
            {
                "msg_id": row[0],
                "receiver_id": row[1],
                "root_fingerprint": row[2],
                "root_epoch": row[3],
                "file_hash": row[4],
                "seen_at": row[5],
                "message_fingerprint": row[6],
            }
            for row in rows
        ],
    }


def forget_seen(path: str | Path, msg_id: str, *, confirm: bool = False) -> dict:
    if not confirm:
        raise VeilDecryptError("Unable to open message.")
    ensure_seen_db(path)
    with sqlite3.connect(path) as conn:
        cur = conn.execute("DELETE FROM seen_messages WHERE msg_id = ?", (msg_id,))
    return {"forgotten": msg_id, "removed": cur.rowcount}


def vacuum_seen(path: str | Path) -> dict:
    ensure_seen_db(path)
    with sqlite3.connect(path) as conn:
        conn.execute("VACUUM")
    return {"database": str(path), "vacuumed": True}


def assert_not_seen(path: str | Path, msg_id: str) -> None:
    ensure_seen_db(path)
    with sqlite3.connect(path) as conn:
        row = conn.execute("SELECT 1 FROM seen_messages WHERE msg_id = ?", (msg_id,)).fetchone()
    if row:
        raise VeilDecryptError("Unable to open message.")


def mark_seen(
    path: str | Path,
    *,
    msg_id: str,
    receiver_id: str,
    root_fingerprint: str,
    root_epoch: int,
    file_hash: str,
    message_fingerprint: str,
) -> None:
    ensure_seen_db(path)
    with sqlite3.connect(path) as conn:
        conn.execute(
            """
            INSERT INTO seen_messages (
                msg_id, receiver_id, root_fingerprint, root_epoch, file_hash, seen_at, message_fingerprint
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (msg_id, receiver_id, root_fingerprint, root_epoch, file_hash, int(time.time()), message_fingerprint),
        )
