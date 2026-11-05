import hashlib
import hmac
import secrets
import sqlite3
import threading

_PASSWORD_ITERATIONS = 200_000
_DEMO_USERNAME = "alice"
_DEMO_PASSWORD = "demo-password"


def _password_hash(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        _PASSWORD_ITERATIONS,
    )


class DemoAuthStore:
    """In-memory SQLite authentication store containing only a fake demo account."""

    def __init__(self) -> None:
        self._connection = sqlite3.connect(":memory:", check_same_thread=False)
        self._lock = threading.Lock()
        self._connection.execute(
            """
            CREATE TABLE demo_users (
                username TEXT PRIMARY KEY,
                password_salt BLOB NOT NULL,
                password_hash BLOB NOT NULL
            )
            """
        )
        salt = secrets.token_bytes(16)
        self._connection.execute(
            """
            INSERT INTO demo_users (username, password_salt, password_hash)
            VALUES (?, ?, ?)
            """,
            (_DEMO_USERNAME, salt, _password_hash(_DEMO_PASSWORD, salt)),
        )
        self._connection.commit()

    def authenticate(self, username: str, password: str) -> bool:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT password_salt, password_hash
                FROM demo_users
                WHERE username = ?
                """,
                (username,),
            ).fetchone()

        if row is None:
            return False

        salt, expected_hash = row
        return hmac.compare_digest(_password_hash(password, salt), expected_hash)


demo_auth_store = DemoAuthStore()
