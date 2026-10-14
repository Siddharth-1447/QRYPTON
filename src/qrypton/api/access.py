"""Server-managed principals; browser role claims never grant permissions.

QRYPTON_ACCESS_TOKENS is a JSON mapping of SHA-256 token digests to
{subject, role}. Provision random access tokens through the deployment secret
manager. Missing credentials have read-only Viewer access.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
import time
from typing import Literal

from fastapi import HTTPException, Request
from pydantic import BaseModel, ValidationError

Role = Literal["Viewer", "Executive", "Security Engineer", "Developer", "CI Publisher"]


class Principal(BaseModel):
    subject: str
    role: Role


_sessions: dict[str, tuple[float, Principal]] = {}
_session_lock = threading.Lock()


def issue_session(actor: Principal) -> str:
    """Issue an expiring opaque credential; store only its digest in memory."""
    token = secrets.token_urlsafe(48)
    with _session_lock:
        now = time.time()
        for key in list(_sessions):
            if _sessions[key][0] <= now:
                del _sessions[key]
        if len(_sessions) >= 4096:
            raise HTTPException(503, "Session capacity reached")
        _sessions[hashlib.sha256(token.encode()).hexdigest()] = (now + 28800, actor)
    return token


def principal(request: Request) -> Principal:
    authorization = request.headers.get("authorization", "")
    if not authorization:
        return Principal(subject="anonymous", role="Viewer")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token or len(token) > 4096:
        raise HTTPException(401, "Invalid access token")
    digest = hashlib.sha256(token.encode()).hexdigest()
    with _session_lock:
        session = _sessions.get(digest)
        if session and session[0] > time.time():
            return session[1]
        _sessions.pop(digest, None)
    try:
        records = json.loads(os.environ.get("QRYPTON_ACCESS_TOKENS", "{}"))
        record = records.get(digest)
        if record is None:
            raise HTTPException(401, "Invalid access token")
        return Principal.model_validate(record)
    except (ValueError, ValidationError, AttributeError) as error:
        raise HTTPException(503, "Workspace access configuration unavailable") from error


def require_engineer(request: Request) -> Principal:
    actor = principal(request)
    if actor.role != "Security Engineer":
        raise HTTPException(403, "Security Engineer role required")
    return actor


def require_ci_publisher(request: Request) -> Principal:
    actor = principal(request)
    if actor.role != "CI Publisher":
        raise HTTPException(403, "CI Publisher role required")
    return actor


def require_ticket_creator(request: Request) -> Principal:
    actor = principal(request)
    if actor.role not in {"Security Engineer", "Developer"}:
        raise HTTPException(403, "Security Engineer or Developer role required")
    return actor
