"""Account export builders for CPA and Sub2API."""
from __future__ import annotations

import base64
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CPA_BASE_URL = "https://cli-chat-proxy.grok.com/v1"
CPA_TOKEN_ENDPOINT = "https://auth.x.ai/oauth2/token"
GROK_CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"
GROK_SCOPE = "openid profile email offline_access grok-cli:access api:access"
GROK_REDIRECT_URI = "http://127.0.0.1:56121/callback"
CPA_HEADERS = {
    "x-grok-client-version": "0.2.93",
    "x-xai-token-auth": "xai-grok-cli",
    "x-authenticateresponse": "authenticate-response",
    "x-grok-client-identifier": "grok-pager",
    "User-Agent": "grok-pager/0.2.93 grok-shell/0.2.93 (linux; x86_64)",
}


def _jwt_payload(token: str) -> dict[str, Any]:
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        data = json.loads(base64.urlsafe_b64decode(part).decode("utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _unix_timestamp(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        pass
    try:
        text = str(value).strip().replace("Z", "+00:00")
        return int(datetime.fromisoformat(text).timestamp())
    except (TypeError, ValueError):
        return None


def _expires_at(record: dict[str, Any]) -> int:
    expires_at = _unix_timestamp(record.get("expires_at") or record.get("expired"))
    if expires_at:
        return expires_at
    claims = _jwt_payload(str(record.get("access_token") or record.get("key") or ""))
    try:
        if claims.get("exp"):
            return int(claims["exp"])
    except (TypeError, ValueError):
        pass
    try:
        return int(time.time()) + int(record.get("expires_in") or 21600)
    except (TypeError, ValueError):
        return int(time.time()) + 21600


def _iso_utc(timestamp: int | float | None) -> str:
    if not timestamp:
        return ""
    return datetime.fromtimestamp(float(timestamp), tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def safe_email_filename(email: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in "._-@" else "_" for ch in email)
    return safe or "unknown"


def build_cpa_record(
    record: dict[str, Any], *, source_file: str = "progrok-registration"
) -> dict[str, Any]:
    access_token = str(record.get("access_token") or record.get("key") or "")
    id_token = str(record.get("id_token") or "")
    claims = _jwt_payload(id_token) or _jwt_payload(access_token)
    email = str(record.get("email") or claims.get("email") or "").strip().lower()
    sub = str(record.get("sub") or claims.get("sub") or claims.get("principal_id") or "")
    return {
        "type": "xai",
        "auth_kind": "oauth",
        "access_token": access_token,
        "refresh_token": str(record.get("refresh_token") or ""),
        "id_token": id_token,
        "token_type": str(record.get("token_type") or "Bearer"),
        "expired": _iso_utc(_expires_at(record)),
        "last_refresh": str(record.get("last_refresh") or _iso_utc(int(time.time()))),
        "email": email,
        "sub": sub,
        "base_url": str(record.get("base_url") or CPA_BASE_URL),
        "token_endpoint": str(record.get("token_endpoint") or CPA_TOKEN_ENDPOINT),
        "redirect_uri": str(record.get("redirect_uri") or GROK_REDIRECT_URI),
        "disabled": bool(record.get("disabled", False)),
        "headers": dict(record.get("headers") or CPA_HEADERS),
        "sso": str(record.get("sso") or ""),
        "password": str(record.get("password") or ""),
        "_source": "grok-register-auto-cpa",
        "_source_file": str(record.get("_source_file") or source_file),
    }


def cpa_filename(record: dict[str, Any]) -> str:
    return f"xai-{safe_email_filename(str(record.get('email') or ''))}.json"


def build_sub2api_payload(records: list[dict[str, Any]]) -> dict[str, Any]:
    accounts: list[dict[str, Any]] = []
    for source in records:
        cpa = build_cpa_record(source)
        credentials: dict[str, Any] = {
            "access_token": cpa["access_token"],
            "refresh_token": cpa["refresh_token"],
            "token_type": cpa["token_type"],
            "client_id": str(source.get("client_id") or source.get("oidc_client_id") or GROK_CLIENT_ID),
            "scope": str(source.get("scope") or GROK_SCOPE),
            "email": cpa["email"],
            "sub": cpa["sub"],
            "expires_at": cpa["expired"],
            "base_url": cpa["base_url"],
        }
        if cpa["id_token"]:
            credentials["id_token"] = cpa["id_token"]
        accounts.append(
            {
                "name": cpa["email"] or "Grok OAuth Account",
                "platform": "grok",
                "type": "oauth",
                "credentials": credentials,
                "extra": {
                    "sso": cpa["sso"],
                    "password": cpa["password"],
                },
                "concurrency": 3,
                "priority": 50,
                "rate_multiplier": 1.0,
                "auto_pause_on_expired": True,
            }
        )
    return {
        "type": "sub2api-data",
        "version": 1,
        "exported_at": _iso_utc(int(time.time())),
        "proxies": [],
        "accounts": accounts,
    }


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
