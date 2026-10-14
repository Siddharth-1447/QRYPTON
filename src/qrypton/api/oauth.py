"""OAuth authorization-code login with PKCE and browser-bound one-use handoffs."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Literal

from fastapi import APIRouter, HTTPException
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from qrypton.api.access import Principal, issue_session

Provider = Literal["google", "github", "gitlab"]
router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])
ENDPOINTS = {
    "google": (
        "https://accounts.google.com/o/oauth2/v2/auth",
        "https://oauth2.googleapis.com/token",
        "https://openidconnect.googleapis.com/v1/userinfo",
        "openid email profile",
    ),
    "github": (
        "https://github.com/login/oauth/authorize",
        "https://github.com/login/oauth/access_token",
        "https://api.github.com/user",
        "read:user user:email",
    ),
    "gitlab": (
        "https://gitlab.com/oauth/authorize",
        "https://gitlab.com/oauth/token",
        "https://gitlab.com/oauth/userinfo",
        "openid email profile",
    ),
}


@dataclass(frozen=True)
class Pending:
    expires: float
    provider: str
    origin: str
    browser_challenge: str
    verifier: str


_pending: dict[str, Pending] = {}
_handoffs: dict[str, tuple[float, str, Principal, str, str | None]] = {}
_lock = threading.Lock()


class LoginStart(BaseModel):
    origin: str = Field(max_length=256)
    challenge: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$")


class LoginExchange(BaseModel):
    code: str = Field(min_length=40, max_length=128)
    verifier: str = Field(pattern=r"^[A-Za-z0-9_-]{43,128}$")
    origin: str = Field(max_length=256)


def challenge(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")


def settings(provider: str) -> tuple[str, str, str]:
    prefix = f"QRYPTON_OAUTH_{provider.upper()}"
    client = os.environ.get(f"{prefix}_CLIENT_ID", "")
    secret = os.environ.get(f"{prefix}_CLIENT_SECRET", "")
    callback = os.environ.get(f"{prefix}_REDIRECT_URI", "")
    parsed = urllib.parse.urlsplit(callback)
    if (
        not client
        or not secret
        or parsed.query
        or parsed.fragment
        or not (
            parsed.scheme == "https"
            or parsed.scheme == "http"
            and parsed.hostname in {"localhost", "127.0.0.1"}
        )
    ):
        raise HTTPException(
            503, f"{provider.title()} sign-in needs administrator OAuth configuration."
        )
    if parsed.path != f"/api/v1/auth/{provider}/callback":
        raise HTTPException(503, "OAuth callback configuration is invalid")
    return client, secret, callback


def _origin(value: str) -> str:
    allowed = os.environ.get(
        "QRYPTON_AUTH_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000"
    ).split(",")
    if value not in [item.strip() for item in allowed]:
        raise HTTPException(400, "Unrecognized application origin")
    return value


def _prune() -> None:
    now = time.time()
    for key in list(_pending):
        if _pending[key].expires <= now:
            del _pending[key]
    for key in list(_handoffs):
        if _handoffs[key][0] <= now:
            del _handoffs[key]


def _request(url: str, data: dict[str, str] | None = None, token: str = "") -> Any:
    headers = {"Accept": "application/json", "User-Agent": "QRYPTON OAuth"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    encoded = urllib.parse.urlencode(data).encode() if data is not None else None
    request = urllib.request.Request(url, data=encoded, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            body = response.read(1_048_577)
        if len(body) > 1_048_576:
            raise ValueError("Oversized response")
        return json.loads(body)
    except (urllib.error.URLError, TimeoutError, ValueError) as error:
        raise HTTPException(502, "Identity provider could not be reached or verified") from error


@router.get("/providers")
def providers() -> dict:
    result = {}
    for provider in ENDPOINTS:
        try:
            settings(provider)
            result[provider] = True
        except HTTPException:
            result[provider] = False
    return {"providers": result, "token_configured": bool(os.environ.get("QRYPTON_ACCESS_TOKENS"))}


@router.post("/{provider}/start")
def start(provider: Provider, body: LoginStart) -> dict[str, str]:
    client, _, callback = settings(provider)
    origin = _origin(body.origin)
    state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(48)
    with _lock:
        _prune()
        if len(_pending) + len(_handoffs) >= 4096:
            raise HTTPException(429, "Too many pending sign-ins")
        _pending[state] = Pending(time.time() + 600, provider, origin, body.challenge, verifier)
    params = {
        "client_id": client,
        "redirect_uri": callback,
        "response_type": "code",
        "scope": ENDPOINTS[provider][3],
        "state": state,
        "code_challenge": challenge(verifier),
        "code_challenge_method": "S256",
    }
    return {"url": ENDPOINTS[provider][0] + "?" + urllib.parse.urlencode(params)}


@router.get("/{provider}/callback")
def callback(provider: Provider, state: str = "", code: str = "", error: str = ""):
    if len(state) > 128 or len(code) > 4096:
        raise HTTPException(400, "Invalid OAuth response")
    with _lock:
        _prune()
        pending = _pending.get(state)
        if pending is None or pending.provider != provider:
            raise HTTPException(400, "Expired or invalid sign-in state")
        del _pending[state]
    failure = pending.origin + "/login#auth_error=Provider%20sign-in%20could%20not%20be%20verified"
    if error or not code:
        return RedirectResponse(failure, status_code=303, headers={"Cache-Control": "no-store"})
    try:
        client, secret, redirect = settings(provider)
        tokens = _request(
            ENDPOINTS[provider][1],
            {
                "grant_type": "authorization_code",
                "code": code,
                "client_id": client,
                "client_secret": secret,
                "redirect_uri": redirect,
                "code_verifier": pending.verifier,
            },
        )
        token = tokens.get("access_token") if isinstance(tokens, dict) else None
        if not isinstance(token, str) or not token or not re.fullmatch(r"[\x21-\x7E]+", token):
            raise HTTPException(401, "Invalid provider token")
        user = _request(ENDPOINTS[provider][2], token=token)
        identifier = user.get("id") if provider == "github" else user.get("sub")
        if not isinstance(identifier, (str, int)) or not str(identifier):
            raise HTTPException(401, "Provider identity unavailable")
        subject = f"{provider}:{identifier}"
        candidate = user.get("email")
        email = (
            candidate
            if isinstance(candidate, str)
            and len(candidate) <= 254
            and re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", candidate)
            and user.get("email_verified") is not False
            else None
        )
        # A social account never grants an administrative role implicitly.
        roles = json.loads(os.environ.get("QRYPTON_OAUTH_ROLES", "{}"))
        actor = Principal(subject=subject, role=roles.get(subject, "Viewer"))
        handoff = secrets.token_urlsafe(48)
        with _lock:
            _handoffs[handoff] = (
                time.time() + 60,
                pending.browser_challenge,
                actor,
                pending.origin,
                email,
            )
        return RedirectResponse(
            pending.origin + "/login#auth_code=" + handoff,
            status_code=303,
            headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
        )
    except (HTTPException, ValueError, AttributeError):
        return RedirectResponse(failure, status_code=303, headers={"Cache-Control": "no-store"})


@router.post("/exchange")
def exchange(body: LoginExchange) -> dict:
    origin = _origin(body.origin)
    with _lock:
        _prune()
        record = _handoffs.get(body.code)
        if (
            record is None
            or record[3] != origin
            or not secrets.compare_digest(record[1], challenge(body.verifier))
        ):
            raise HTTPException(401, "Expired or invalid sign-in handoff")
        del _handoffs[body.code]
    return {"access_token": issue_session(record[2]), **record[2].model_dump(), "email": record[4]}
