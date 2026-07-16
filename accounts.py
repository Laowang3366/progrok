"""Filesystem-backed account sink used by the standalone registration adapter."""
from __future__ import annotations

import base64
import json
import os
import re
import threading
import uuid
from pathlib import Path
from typing import Any

from export_formats import build_cpa_record, build_sub2api_payload, cpa_filename

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
ACCOUNTS_DIR = DATA_DIR / "accounts"
MERGED_AUTH = DATA_DIR / "auth.json"
_lock = threading.RLock()


def _jwt_payload(token: str) -> dict[str, Any]:
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part).decode("utf-8"))
    except Exception:
        return {}


def _safe_name(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    return value[:100] or "account"


def _atomic_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def import_auth_payload(
    payload: dict[str, Any],
    merge: bool = True,
    output_format: str = "cpa",
) -> dict[str, Any]:
    access_token = str(payload.get("key") or "").strip()
    if not access_token:
        return {"ok": False, "error": "auth payload missing access token"}

    claims = _jwt_payload(access_token)
    account_id = str(claims.get("sub") or claims.get("principal_id") or uuid.uuid4())
    email = str(payload.get("email") or claims.get("email") or "").strip().lower()
    issuer = str(payload.get("oidc_issuer") or "https://auth.x.ai")
    client_id = str(payload.get("oidc_client_id") or "b1a00492-073a-47ea-816f-4c329264a828")
    entry = {
        "key": access_token,
        "auth_mode": str(payload.get("auth_mode") or "oidc"),
        "refresh_token": str(payload.get("refresh_token") or ""),
        "expires_at": payload.get("expires_at"),
        "user_id": account_id,
        "principal_id": str(claims.get("principal_id") or account_id),
        "principal_type": str(claims.get("principal_type") or "User"),
        "email": email,
        "oidc_issuer": issuer,
        "oidc_client_id": client_id,
    }
    auth_key = f"{issuer}::{client_id}"
    unique_key = f"{auth_key}::{account_id}"
    cpa_record = build_cpa_record(payload)
    normalized_format = str(output_format or "cpa").strip().lower()
    if normalized_format == "sub2api":
        output_record = build_sub2api_payload([cpa_record])
        filename = cpa_filename(cpa_record).replace("xai-", "sub2api-", 1)
    else:
        normalized_format = "cpa"
        output_record = cpa_record
        filename = cpa_filename(cpa_record)
    target = ACCOUNTS_DIR / filename

    with _lock:
        _atomic_json(target, output_record)
        merged: dict[str, Any] = {}
        if merge and MERGED_AUTH.exists():
            try:
                loaded = json.loads(MERGED_AUTH.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    merged = loaded
            except Exception:
                merged = {}
        merged[unique_key] = entry
        _atomic_json(MERGED_AUTH, merged)

    row = {
        "id": account_id,
        "email": email,
        "path": str(target),
        "format": normalized_format,
    }
    return {
        "ok": True,
        "storage": "filesystem",
        "imported": [row],
        "auth_file": str(MERGED_AUTH),
    }
