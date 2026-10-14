"""Local password accounts. Registration never grants workspace write privileges."""

from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import threading
import time
from collections import deque
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator

from qrypton.api.access import Principal, issue_session

router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])
_lock = threading.Lock()
_attempts: dict[str, deque[float]] = {}
_hash_slots = threading.BoundedSemaphore(4)
_dummy_salt = secrets.token_bytes(32)


class Credentials(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=128, repr=False)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        value = value.strip().casefold()
        local, separator, domain = value.partition("@")
        if (
            not separator
            or not local
            or "." not in domain
            or "@" in domain
            or any(char.isspace() or ord(char) < 33 for char in value)
        ):
            raise ValueError("Enter a valid email address")
        return value


def _tenant() -> str:
    return os.environ.get("QRYPTON_TENANT_ID", "tenant_" + "a" * 52)


@contextmanager
def _database() -> Iterator[sqlite3.Connection]:
    path = Path(os.environ.get("QRYPTON_AUTH_DB", "qrypton-accounts.sqlite3"))
    try:
        db = sqlite3.connect(path, timeout=5)
        db.execute("""CREATE TABLE IF NOT EXISTS accounts (
            tenant TEXT NOT NULL, email TEXT NOT NULL, subject TEXT NOT NULL,
            salt BLOB NOT NULL, password_hash BLOB NOT NULL, created REAL NOT NULL,
            PRIMARY KEY(tenant, email))""")
        try:
            yield db
        finally:
            db.close()
    except sqlite3.Error as error:
        raise HTTPException(503, "Account service unavailable. Please retry.") from error


def _rate_limit(request: Request, email: str) -> None:
    # Use the socket peer, never a caller-supplied forwarded IP.
    peer = request.client.host if request.client else "unknown"
    keys = (f"ip:{peer}", "account:" + hashlib.sha256(email.encode()).hexdigest())
    now = time.monotonic()
    with _lock:
        for key in list(_attempts):
            while _attempts[key] and _attempts[key][0] < now - 300:
                _attempts[key].popleft()
            if not _attempts[key]:
                del _attempts[key]
        if len(_attempts) >= 10000 or any(
            len(_attempts.get(key, ())) >= limit for key, limit in zip(keys, (30, 10), strict=True)
        ):
            raise HTTPException(
                429, "Too many attempts. Try again in five minutes.", headers={"Retry-After": "300"}
            )
        for key in keys:
            _attempts.setdefault(key, deque()).append(now)


def _hash(password: str, salt: bytes) -> bytes:
    if not _hash_slots.acquire(blocking=False):
        raise HTTPException(503, "Sign-in is busy. Please retry.")
    try:
        return hashlib.scrypt(
            password.encode(), salt=salt, n=131072, r=8, p=1, maxmem=256 * 1024 * 1024, dklen=32
        )
    finally:
        _hash_slots.release()


def _session(subject: str, email: str, response: Response) -> dict[str, str]:
    response.headers["Cache-Control"] = "no-store"
    actor = Principal(subject=subject, role="Viewer")
    return {
        "access_token": issue_session(actor),
        "subject": subject,
        "role": actor.role,
        "email": email,
    }


@router.post("/signup", status_code=201)
def signup(body: Credentials, request: Request, response: Response) -> dict[str, str]:
    _rate_limit(request, body.email)
    if os.environ.get("QRYPTON_ALLOW_SIGNUP", "true").lower() != "true":
        raise HTTPException(
            403, "Account creation is disabled. Contact your workspace administrator."
        )
    if len(body.password) < 12:
        raise HTTPException(422, "Use a password with at least 12 characters.")
    salt = secrets.token_bytes(32)
    digest = _hash(body.password, salt)
    subject = "account:" + secrets.token_urlsafe(24)
    with _database() as db:
        try:
            with db:
                db.execute(
                    "INSERT INTO accounts VALUES (?, ?, ?, ?, ?, ?)",
                    (_tenant(), body.email, subject, salt, digest, time.time()),
                )
        except sqlite3.IntegrityError as error:
            raise HTTPException(
                409, "Account could not be created. Try signing in instead."
            ) from error
    return _session(subject, body.email, response)


@router.post("/signin")
def signin(body: Credentials, request: Request, response: Response) -> dict[str, str]:
    _rate_limit(request, body.email)
    with _database() as db:
        row = db.execute(
            "SELECT subject, salt, password_hash FROM accounts WHERE tenant=? AND email=?",
            (_tenant(), body.email),
        ).fetchone()
    digest = _hash(body.password, row[1] if row else _dummy_salt)
    if row is None or not secrets.compare_digest(digest, row[2]):
        raise HTTPException(
            401, "Account not found or password incorrect. Check your details or create an account."
        )
    return _session(row[0], body.email, response)
