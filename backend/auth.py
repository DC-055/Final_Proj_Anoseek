"""
Minimal auth for ANOSEEK.

Backs the /login endpoint and the require_admin dependency used to gate
admin-only routes (currently: reading/writing the agent policy).

Users live in backend/data/system_users.db (username, password hash, role).
Tokens are HS256 JWTs signed with AUTH_SECRET_KEY (see backend/.env).

No external JWT/hashing libraries are used (pip has no network access in
this environment) — HS256 signing and PBKDF2 hashing are both implemented
with stdlib `hmac`/`hashlib`, which is sufficient for this project's needs.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from pathlib import Path

from dotenv import load_dotenv
from fastapi import Header, HTTPException

load_dotenv()

DATA_DIR = Path(__file__).resolve().parent / "data"
DB_PATH = DATA_DIR / "system_users.db"

TOKEN_TTL_SECONDS = 8 * 3600
ROLES = ("SOC", "ADMIN")

_SECRET_KEY = os.environ.get("AUTH_SECRET_KEY")
if not _SECRET_KEY:
    _SECRET_KEY = secrets.token_hex(32)
    print(
        "[auth] WARNING: AUTH_SECRET_KEY not set in backend/.env — using a "
        "random key for this process only. All tokens will be invalidated "
        "on restart. Set AUTH_SECRET_KEY for a stable, real deployment."
    )
SECRET_KEY = _SECRET_KEY.encode("utf-8")


# ---------------------------------------------------------------- database

def init_db() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS system_users (
                username TEXT NOT NULL CHECK(LENGTH(username) >= 3) PRIMARY KEY,
                password TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                role TEXT CHECK(role IN ('SOC', 'ADMIN'))
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------- passwords

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split("$", 1)
    except ValueError:
        return False
    salt = bytes.fromhex(salt_hex)
    expected = bytes.fromhex(digest_hex)
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return hmac.compare_digest(actual, expected)


def create_user(username: str, password: str, role: str) -> None:
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")
    if len(password) < 8:
        raise ValueError("password must be at least 8 characters")
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            "INSERT INTO system_users (username, password, role) VALUES (?, ?, ?)",
            (username, hash_password(password), role),
        )
        conn.commit()
    finally:
        conn.close()


def authenticate(username: str, password: str) -> str | None:
    """Returns the user's role on success, None on bad credentials."""
    conn = sqlite3.connect(DB_PATH)
    try:
        row = conn.execute(
            "SELECT password, role FROM system_users WHERE username = ?",
            (username,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    stored_password, role = row
    if not verify_password(password, stored_password):
        return None
    return role


# ---------------------------------------------------------------- JWT (HS256)

def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def create_token(username: str, role: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    payload = {"sub": username, "role": role, "iat": now, "exp": now + TOKEN_TTL_SECONDS}

    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = hmac.new(SECRET_KEY, signing_input, hashlib.sha256).digest()
    sig_b64 = _b64url_encode(signature)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


class TokenError(Exception):
    pass


def decode_token(token: str) -> dict:
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except ValueError:
        raise TokenError("Malformed token")

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    expected_sig = hmac.new(SECRET_KEY, signing_input, hashlib.sha256).digest()
    try:
        actual_sig = _b64url_decode(sig_b64)
    except Exception:
        raise TokenError("Malformed signature")
    if not hmac.compare_digest(actual_sig, expected_sig):
        raise TokenError("Invalid signature")

    try:
        payload = json.loads(_b64url_decode(payload_b64))
    except Exception:
        raise TokenError("Malformed payload")

    if payload.get("exp", 0) < time.time():
        raise TokenError("Token expired")

    return payload


# ---------------------------------------------------------------- FastAPI dependency

def require_admin(authorization: str | None = Header(default=None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing bearer token")
    token = authorization.removeprefix("Bearer ").strip()
    try:
        payload = decode_token(token)
    except TokenError as e:
        raise HTTPException(401, str(e))
    if payload.get("role") != "ADMIN":
        raise HTTPException(403, "ADMIN role required")
    return payload
