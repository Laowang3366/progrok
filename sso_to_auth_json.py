#!/usr/bin/env python3
"""
批量导入 xAI SSO cookie 到项目 auth.json（纯 HTTP Device Flow）

用法:
  # 单个 / 批量 SSO，每个导入后按 user_id 合并到 data/auth.json
  python3 sso_to_auth_json.py --sso sso_list.txt

  # 写出多个独立 auth 文件（每个可直接 cp 到 ~/.grok/auth.json）
  python3 sso_to_auth_json.py --sso sso_list.txt --out-dir ./auth_out

  # 合并到指定 json（key 带 user_id 后缀，避免覆盖）
  python3 sso_to_auth_json.py --sso sso_list.txt --out auth_merged.json --merge

  # 单行 sso
  python3 sso_to_auth_json.py --sso-cookie 'eyJ...'

环境变量:
  GROK2API_AUTH_FILE  - 导入目标 auth.json（默认项目 data/auth.json）
  GROK2API_PROXY      - 代理地址，例如 http://127.0.0.1:7890
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from curl_cffi import requests

# Use project config when available, otherwise fall back to defaults
try:
    from config import AUTH_FILE, GROK_CLI_CLIENT_ID, OIDC_ISSUER, OIDC_SCOPES
except Exception:  # pragma: no cover - standalone fallback
    AUTH_FILE = Path(os.getenv("GROK2API_AUTH_FILE", str(Path.home() / ".grok" / "auth.json")))
    GROK_CLI_CLIENT_ID = os.getenv("GROK2API_OIDC_CLIENT_ID", "b1a00492-073a-47ea-816f-4c329264a828")
    OIDC_ISSUER = os.getenv("GROK2API_OIDC_ISSUER", "https://auth.x.ai")
    OIDC_SCOPES = os.getenv(
        "GROK2API_OIDC_SCOPES",
        "openid profile email offline_access grok-cli:access "
        "api:access conversations:read conversations:write",
    )

AUTH_KEY = f"{OIDC_ISSUER}::{GROK_CLI_CLIENT_ID}"

# Serialize / throttle OIDC device-flow across concurrent registration workers.
# xAI returns HTTP 429 slow_down / rate_limited when many device/code+verify
# requests fan out together — that is the "two consecutive failures" pattern.
import threading as _threading

_DEVICE_FLOW_LOCK = _threading.RLock()
_DEVICE_FLOW_LAST_TS = 0.0


def _device_flow_gap_sec() -> float:
    try:
        return max(0.0, float(os.getenv("GROK2API_SSO_DEVICE_GAP_SEC", "1.2") or 1.2))
    except (TypeError, ValueError):
        return 1.2


def _device_flow_retries() -> int:
    try:
        return max(1, min(6, int(os.getenv("GROK2API_SSO_DEVICE_RETRIES", "3") or 3)))
    except (TypeError, ValueError):
        return 3


def _device_flow_backoff_sec(attempt: int) -> float:
    # attempt is 1-based after a failure
    base = 2.0 * attempt
    try:
        base = float(os.getenv("GROK2API_SSO_DEVICE_BACKOFF_SEC", str(base)) or base)
    except (TypeError, ValueError):
        pass
    return max(1.0, min(20.0, base))


def _wait_device_flow_slot() -> None:
    """Global min-gap between device-flow starts (cross-thread)."""
    global _DEVICE_FLOW_LAST_TS
    gap = _device_flow_gap_sec()
    with _DEVICE_FLOW_LOCK:
        now = time.time()
        wait = (_DEVICE_FLOW_LAST_TS + gap) - now
        if wait > 0:
            time.sleep(wait)
        _DEVICE_FLOW_LAST_TS = time.time()


def _is_rate_limited_payload(text: str | None = None, url: str | None = None, status: int | None = None) -> bool:
    blob = f"{status or ''} {url or ''} {text or ''}".lower()
    return any(
        k in blob
        for k in (
            "slow_down",
            "rate_limited",
            "rate limit",
            "too many",
            "429",
        )
    )



def _proxy_kwargs() -> dict:
    """Return curl_cffi compatible proxy kwargs from env / proxy pool."""
    try:
        from proxy_pool import resolve_proxy_for_request, curl_proxies_arg

        url = resolve_proxy_for_request(fallback_env=True)
        proxies = curl_proxies_arg(url)
        if proxies:
            return {"proxies": proxies}
    except Exception:
        pass
    proxy = (
        os.getenv("GROK2API_XAI_PROXY")
        or os.getenv("GROK2API_PROXY")
        or os.getenv("GROK_CLI_PROXY")
        or ""
    ).strip()
    # Multi-line: take first non-empty line.
    if "\n" in proxy or "\r" in proxy:
        proxy = next(
            (
                ln.strip()
                for ln in proxy.replace("\r", "\n").split("\n")
                if ln.strip() and not ln.strip().startswith("#")
            ),
            "",
        )
    if proxy:
        return {"proxies": {"http": proxy, "https": proxy}}
    return {}


def b64url_decode(seg: str) -> bytes:
    seg += "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg)


def decode_jwt_payload(token: str) -> dict:
    try:
        return json.loads(b64url_decode(token.split(".")[1]))
    except Exception:
        return {}


def rfc3339_ns(ts: float | None = None) -> str:
    """2026-07-10T01:00:00.000000000Z"""
    if ts is None:
        ts = time.time()
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + ".000000000Z"


def _http_timeout() -> float:
    try:
        return max(5.0, float(os.getenv("GROK2API_SSO_HTTP_TIMEOUT", "12") or 12))
    except (TypeError, ValueError):
        return 12.0


def _poll_interval_sec(raw: Any = None) -> float:
    """Device-code poll interval after approve.

    Upstream often advertises interval=5, but once the user_code is already
    approved we can poll immediately / more aggressively. Override with
    GROK2API_SSO_POLL_INTERVAL (seconds).
    """
    env = (os.getenv("GROK2API_SSO_POLL_INTERVAL") or "").strip()
    if env:
        try:
            return max(0.2, min(10.0, float(env)))
        except ValueError:
            pass
    try:
        hinted = float(raw if raw is not None else 1)
    except (TypeError, ValueError):
        hinted = 1.0
    # Prefer 1s (or the advertised value if already smaller) after approve.
    return max(0.4, min(hinted, 1.5))


def request_device_code(session: Any | None = None) -> dict | None:
    """Request OIDC device code. Prefer shared curl_cffi session when given.

    Retries on xAI rate limits (HTTP 429 / slow_down) — common when several
    registration workers enter device-flow together.
    """
    form = {"client_id": GROK_CLI_CLIENT_ID, "scope": OIDC_SCOPES}
    timeout = _http_timeout()
    retries = _device_flow_retries()
    last_err = ""
    for attempt in range(1, retries + 1):
        _wait_device_flow_slot()
        if session is not None:
            try:
                r = session.post(
                    f"{OIDC_ISSUER}/oauth2/device/code",
                    data=form,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    impersonate="chrome",
                    timeout=timeout,
                    **_proxy_kwargs(),
                )
                code = int(getattr(r, "status_code", 0) or 0)
                body = (getattr(r, "text", None) or "")[:300]
                if code >= 400:
                    last_err = f"HTTP {code}: {body[:200]}"
                    print(f"  ❌ device/code {last_err}")
                    if _is_rate_limited_payload(body, status=code) and attempt < retries:
                        time.sleep(_device_flow_backoff_sec(attempt))
                        continue
                    return None
                data = r.json()
                return data if isinstance(data, dict) else None
            except Exception as e:  # noqa: BLE001
                last_err = str(e)
                print(f"  ❌ device/code: {e}")
                if attempt < retries and _is_rate_limited_payload(str(e)):
                    time.sleep(_device_flow_backoff_sec(attempt))
                    continue
                return None

        data = urllib.parse.urlencode(form).encode()
        req = urllib.request.Request(
            f"{OIDC_ISSUER}/oauth2/device/code",
            data=data,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            body = e.read().decode()[:300]
            last_err = f"HTTP {e.code}: {body[:200]}"
            print(f"  ❌ device/code {last_err}")
            if _is_rate_limited_payload(body, status=e.code) and attempt < retries:
                time.sleep(_device_flow_backoff_sec(attempt))
                continue
            return None
        except Exception as e:  # noqa: BLE001
            last_err = str(e)
            print(f"  ❌ device/code: {e}")
            if attempt < retries:
                time.sleep(_device_flow_backoff_sec(attempt))
                continue
            return None
    if last_err:
        print(f"  ❌ device/code exhausted retries: {last_err}")
    return None


def poll_token(
    device_code: str,
    interval: int | float = 1,
    expires_in: int = 1800,
    timeout: int | float = 45,
    *,
    session: Any | None = None,
    immediate: bool = True,
) -> dict | None:
    """Exchange an approved device_code for tokens.

    Performance notes:
    - Poll **immediately** after approve (do not sleep first).
    - Use a short interval (default ~1s) instead of the upstream 5s hint.
    - Prefer curl_cffi session when provided (same TLS fingerprint path).
    """
    interval_f = _poll_interval_sec(interval)
    deadline = time.time() + min(float(expires_in or 1800), float(timeout or 45))
    form = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": GROK_CLI_CLIENT_ID,
        "device_code": device_code,
    }
    http_timeout = _http_timeout()
    first = True
    while time.time() < deadline:
        if not (first and immediate):
            time.sleep(interval_f)
        first = False

        if session is not None:
            try:
                r = session.post(
                    f"{OIDC_ISSUER}/oauth2/token",
                    data=form,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    impersonate="chrome",
                    timeout=http_timeout,
                    **_proxy_kwargs(),
                )
                code = int(getattr(r, "status_code", 0) or 0)
                if code < 400:
                    data = r.json()
                    return data if isinstance(data, dict) else None
                try:
                    err = r.json() if r.content else {}
                except Exception:
                    err = {}
                error = str((err or {}).get("error") or "")
                if error == "authorization_pending":
                    continue
                if error == "slow_down":
                    interval_f = min(10.0, interval_f + 1.0)
                    continue
                print(f"  ❌ token: {error or f'HTTP {code}'}")
                return None
            except Exception as e:  # noqa: BLE001
                # Transient network blip — retry until deadline.
                if time.time() >= deadline:
                    print(f"  ❌ token network: {e}")
                    return None
                continue

        data = urllib.parse.urlencode(form).encode()
        req = urllib.request.Request(
            f"{OIDC_ISSUER}/oauth2/token",
            data=data,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            with urllib.request.urlopen(req, timeout=http_timeout) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            try:
                err = json.loads(e.read())
            except Exception:
                err = {}
            error = err.get("error", "")
            if error == "authorization_pending":
                continue
            if error == "slow_down":
                interval_f = min(10.0, interval_f + 1.0)
                continue
            print(f"  ❌ token: {error}")
            return None
        except Exception as e:  # noqa: BLE001
            if time.time() >= deadline:
                print(f"  ❌ token network: {e}")
                return None
            continue
    print("  ❌ 轮询超时")
    return None


def sso_to_token(sso_cookie: str, *, quiet: bool = False) -> dict | None:
    """SSO cookie → token dict (access/refresh/expires_in).

    ``quiet=True`` reduces per-account stdout (faster under high concurrency).

    Retries the full device flow on xAI rate limits (device/code 429 slow_down,
    verify/approve ``rate_limited``). Concurrent registration workers otherwise
    produce consecutive conversion failures after SSO was already obtained.
    """
    log = (lambda *a, **k: None) if quiet else print
    s = requests.Session()
    s.cookies.set("sso", sso_cookie, domain=".x.ai")
    timeout = _http_timeout()
    proxy_kw = _proxy_kwargs()

    try:
        r = s.get(
            "https://accounts.x.ai/",
            impersonate="chrome",
            timeout=timeout,
            **proxy_kw,
        )
    except Exception as e:
        log(f"  ❌ 网络错误: {e}")
        return None
    if "sign-in" in r.url or "sign-up" in r.url:
        log("  ❌ sso 无效")
        return None
    log("  ✅ sso 有效")

    retries = _device_flow_retries()
    for attempt in range(1, retries + 1):
        log(f"  🔑 Device Flow... (try {attempt}/{retries})")
        dc = request_device_code(session=s)
        if not dc:
            if attempt < retries:
                time.sleep(_device_flow_backoff_sec(attempt))
                continue
            return None
        log(f"  📋 user_code: {dc.get('user_code')}")

        rate_limited = False
        try:
            s.get(
                dc["verification_uri_complete"],
                impersonate="chrome",
                timeout=timeout,
                **proxy_kw,
            )
            r = s.post(
                f"{OIDC_ISSUER}/oauth2/device/verify",
                data={"user_code": dc["user_code"]},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                impersonate="chrome",
                timeout=timeout,
                allow_redirects=True,
                **proxy_kw,
            )
            if "consent" not in (r.url or ""):
                log(f"  ❌ verify 失败: {r.url}")
                if _is_rate_limited_payload(getattr(r, "text", None), r.url, getattr(r, "status_code", None)):
                    rate_limited = True
                else:
                    return None
        except Exception as e:
            log(f"  ❌ verify 异常: {e}")
            if _is_rate_limited_payload(str(e)):
                rate_limited = True
            else:
                return None
        if rate_limited:
            if attempt < retries:
                time.sleep(_device_flow_backoff_sec(attempt))
                continue
            return None

        try:
            r = s.post(
                f"{OIDC_ISSUER}/oauth2/device/approve",
                data={
                    "user_code": dc["user_code"],
                    "action": "allow",
                    "principal_type": "User",
                    "principal_id": "",
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                impersonate="chrome",
                timeout=timeout,
                allow_redirects=True,
                **proxy_kw,
            )
            if "done" not in (r.url or ""):
                log(f"  ❌ approve 失败: {r.url}")
                if _is_rate_limited_payload(getattr(r, "text", None), r.url, getattr(r, "status_code", None)):
                    if attempt < retries:
                        time.sleep(_device_flow_backoff_sec(attempt))
                        continue
                return None
            log("  ✅ 授权确认")
        except Exception as e:
            log(f"  ❌ approve 异常: {e}")
            if _is_rate_limited_payload(str(e)) and attempt < retries:
                time.sleep(_device_flow_backoff_sec(attempt))
                continue
            return None

        # Approve already happened — poll immediately with a short interval.
        token = poll_token(
            dc["device_code"],
            dc.get("interval", 1),
            dc.get("expires_in", 1800),
            timeout=float(os.getenv("GROK2API_SSO_POLL_TIMEOUT", "45") or 45),
            session=s,
            immediate=True,
        )
        if not token:
            if attempt < retries:
                log("  ⏳ token poll empty — retry device flow")
                time.sleep(_device_flow_backoff_sec(attempt))
                continue
            return None
        log(
            f"  ✅ access_token (expires_in={token.get('expires_in')}s)"
            + (" + refresh_token" if token.get("refresh_token") else "")
        )
        return token
    return None


def token_to_auth_entry(token: dict, email: str = "") -> tuple[str, dict]:
    """
    返回 (top_level_key, entry)
    top_level_key 固定为 issuer::client_id（与 ~/.grok/auth.json 一致）
    """
    access = token.get("access_token") or token.get("key") or ""
    refresh = token.get("refresh_token") or ""
    payload = decode_jwt_payload(access)

    user_id = payload.get("sub") or payload.get("principal_id") or ""
    principal_id = payload.get("principal_id") or user_id
    principal_type = payload.get("principal_type") or "User"

    expires_in = int(token.get("expires_in") or 21600)
    if "exp" in payload:
        expires_at = rfc3339_ns(float(payload["exp"]))
    else:
        expires_at = rfc3339_ns(time.time() + expires_in)

    iat = payload.get("iat")
    create_time = rfc3339_ns(float(iat) if iat else time.time())

    entry = {
        "key": access,
        "auth_mode": "oidc",
        "create_time": create_time,
        "user_id": user_id,
        "email": email or payload.get("email") or "",
        "principal_type": principal_type,
        "principal_id": principal_id,
        "refresh_token": refresh,
        "expires_at": expires_at,
        "oidc_issuer": OIDC_ISSUER,
        "oidc_client_id": GROK_CLI_CLIENT_ID,
    }
    return AUTH_KEY, entry


def write_auth_json(path: Path, auth_key: str, entry: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {auth_key: entry}
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def merge_auth_json(path: Path, auth_key: str, entry: dict, unique: bool = True) -> None:
    """
    合并写入。unique=True 时 key 变成 issuer::client_id::user_id，避免多账号互相覆盖。
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    existing: dict = {}
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            existing = {}
    key = auth_key
    if unique and entry.get("user_id"):
        key = f"{auth_key}::{entry['user_id']}"
    existing[key] = entry
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(existing, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def import_into_project_auth(entry: dict) -> str:
    """Use project's account manager to merge entry into AUTH_FILE."""
    import accounts as _accounts

    # Build a single-entry payload; _normalize_entry will derive user_id/email/expires_at.
    payload = {
        "key": entry["key"],
        "auth_mode": entry.get("auth_mode", "oidc"),
        "email": entry.get("email", ""),
        "refresh_token": entry.get("refresh_token", ""),
        "expires_at": entry.get("expires_at"),
        "oidc_issuer": entry.get("oidc_issuer", OIDC_ISSUER),
        "oidc_client_id": entry.get("oidc_client_id", GROK_CLI_CLIENT_ID),
    }
    result = _accounts.import_auth_payload(payload, merge=True)
    if not result.get("ok"):
        raise RuntimeError(result.get("error") or "import failed")
    imported = result.get("imported", [])
    return imported[0] if imported else ""


def load_sso_list(path: str | None, single: str | None) -> list[tuple[str, str]]:
    """Return list of (email_or_name, sso_cookie) tuples."""
    if single:
        return [("", single.strip())]
    if not path:
        return []
    out: list[tuple[str, str]] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        email = ""
        # 兼容 邮箱----密码----sso 或 邮箱:密码:sso
        if "----" in line:
            parts = line.split("----")
            email = parts[0].strip()
            line = parts[-1].strip()
        elif ":" in line and not line.startswith("eyJ"):
            parts = line.rsplit(":", 1)
            email = parts[0].strip()
            line = parts[-1].strip()
        out.append((email, line))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="SSO cookie → grok auth.json (纯 HTTP)")
    ap.add_argument("--sso", metavar="FILE", help="sso 列表文件（一行一个 JWT，或 邮箱----密码----sso）")
    ap.add_argument("--sso-cookie", metavar="JWT", help="单个 sso cookie")
    ap.add_argument("--out", default=None, help="输出 auth.json 路径（单账号或 --merge）")
    ap.add_argument(
        "--out-dir",
        default=None,
        help="批量时每个账号写一个 {user_id}.json（可直接 cp 到 ~/.grok/auth.json）",
    )
    ap.add_argument(
        "--merge",
        action="store_true",
        help="合并到 --out，key 用 issuer::client_id::user_id",
    )
    ap.add_argument(
        "--into-project",
        action="store_true",
        default=True,
        help=f"默认导入到项目 auth.json: {AUTH_FILE}",
    )
    ap.add_argument(
        "--no-into-project",
        dest="into_project",
        action="store_false",
        help="不导入项目 auth.json，仅 --out / --out-dir 输出",
    )
    ap.add_argument("--delay", type=int, default=0, help="每个间隔秒数")
    ap.add_argument("--email", default="", help="写入 entry.email（可选）")
    args = ap.parse_args()

    cookies = load_sso_list(args.sso, args.sso_cookie)
    if not cookies:
        ap.error("需要 --sso 或 --sso-cookie")

    if len(cookies) > 1 and not args.out_dir and not args.merge and not args.into_project:
        args.out_dir = args.out_dir or "./auth_out"
        print(f"批量模式默认 --out-dir {args.out_dir}")

    if args.out is None and args.out_dir is None and len(cookies) == 1 and not args.into_project:
        args.out = str(Path.home() / ".grok" / "auth.json")

    target = "项目 auth.json" if args.into_project else (args.out or args.out_dir or "stdout")
    print(f"🚀 SSO → auth.json: {len(cookies)} 个, target={target}, delay={args.delay}s")
    ok = 0
    fail = 0

def process_one_sso(
    index: int,
    email_hint: str,
    sso: str,
    *,
    args_email: str,
    into_project: bool,
    out_dir: Path | None,
    out: Path | None,
    merge: bool,
    total: int,
) -> dict[str, Any]:
    """Process a single SSO cookie. Thread-safe for independent accounts."""
    result: dict[str, Any] = {"index": index, "email_hint": email_hint, "sso_hint": sso[:12] + "..." if len(sso) > 12 else "..."}
    try:
        token = sso_to_token(sso)
        if not token:
            result["status"] = "failed"
            result["error"] = "device flow failed or invalid sso"
            return result
        key, entry = token_to_auth_entry(token, email=args_email or email_hint)
        uid = entry.get("user_id") or secrets.token_hex(4)

        if out_dir:
            p = out_dir / f"{uid}.json"
            write_auth_json(p, key, entry)
            result["wrote"] = str(p)
        if out:
            if merge or total > 1:
                merge_auth_json(out, key, entry, unique=True)
                result["merged"] = str(out)
            else:
                write_auth_json(out, key, entry)
                result["wrote"] = str(out)
        if into_project:
            aid = import_into_project_auth(entry)
            result["imported_key"] = aid

        result["status"] = "ok"
        result["user_id"] = uid
        result["email"] = entry.get("email")
        return result
    except Exception as e:
        result["status"] = "failed"
        result["error"] = str(e)
        return result


def run_concurrent(
    cookies: list[tuple[str, str]],
    *,
    max_workers: int,
    delay: int,
    args_email: str,
    into_project: bool,
    out_dir: Path | None,
    out: Path | None,
    merge: bool,
) -> tuple[int, int, list[dict[str, Any]]]:
    """Run SSO imports concurrently with per-item delay handled inside threads."""
    results: list[dict[str, Any]] = [None] * len(cookies)
    ok = 0
    fail = 0

    def _worker(args: tuple[int, str, str]) -> tuple[int, dict[str, Any]]:
        i, email_hint, sso = args
        if delay > 0 and i > 1:
            time.sleep(delay * (i - 1))
        res = process_one_sso(
            i,
            email_hint,
            sso,
            args_email=args_email,
            into_project=into_project,
            out_dir=out_dir,
            out=out,
            merge=merge,
            total=len(cookies),
        )
        print(
            f"\n{'=' * 60}\n[{i}/{len(cookies)}] {email_hint or ''}\n{'=' * 60}"
        )
        for k, v in res.items():
            if k in ("index", "email_hint", "sso_hint"):
                continue
            if k == "status":
                mark = "✅" if v == "ok" else "❌"
                print(f"  {mark} [{i}] {v}")
            elif isinstance(v, str):
                print(f"  💾 {k}: {v}")
            else:
                print(f"  • {k}: {v}")
        return i - 1, res

    workers = min(max_workers, max(1, len(cookies)))
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="sso-") as ex:
        for idx, res in ex.map(_worker, ((i, e, s) for i, (e, s) in enumerate(cookies, 1))):
            results[idx] = res
            if res.get("status") == "ok":
                ok += 1
            else:
                fail += 1

    return ok, fail, results


def main() -> int:
    ap = argparse.ArgumentParser(description="SSO cookie → grok auth.json (纯 HTTP)")
    ap.add_argument("--sso", metavar="FILE", help="sso 列表文件（一行一个 JWT，或 邮箱----密码----sso）")
    ap.add_argument("--sso-cookie", metavar="JWT", help="单个 sso cookie")
    ap.add_argument("--out", default=None, help="输出 auth.json 路径（单账号或 --merge）")
    ap.add_argument(
        "--out-dir",
        default=None,
        help="批量时每个账号写一个 {user_id}.json（可直接 cp 到 ~/.grok/auth.json）",
    )
    ap.add_argument(
        "--merge",
        action="store_true",
        help="合并到 --out，key 用 issuer::client_id::user_id",
    )
    ap.add_argument(
        "--into-project",
        action="store_true",
        default=True,
        help=f"默认导入到项目 auth.json: {AUTH_FILE}",
    )
    ap.add_argument(
        "--no-into-project",
        dest="into_project",
        action="store_false",
        help="不导入项目 auth.json，仅 --out / --out-dir 输出",
    )
    ap.add_argument("--delay", type=int, default=0, help="每个间隔秒数")
    ap.add_argument("--email", default="", help="写入 entry.email（可选）")
    ap.add_argument(
        "--threads",
        type=int,
        default=4,
        help="并发线程数（默认 4，最大 8；大量 SSO 时过高会冻 WSL）",
    )
    args = ap.parse_args()

    cookies = load_sso_list(args.sso, args.sso_cookie)
    if not cookies:
        ap.error("需要 --sso 或 --sso-cookie")

    # Hard cap: each worker opens a curl_cffi chrome session; 700× freezes WSL
    threads = max(1, min(int(args.threads or 4), 8))
    if threads != args.threads:
        print(f"⚠️  threads {args.threads} → capped to {threads}")
    args.threads = threads

    if len(cookies) > 1 and not args.out_dir and not args.merge and not args.into_project:
        args.out_dir = args.out_dir or "./auth_out"
        print(f"批量模式默认 --out-dir {args.out_dir}")

    if args.out is None and args.out_dir is None and len(cookies) == 1 and not args.into_project:
        args.out = str(Path.home() / ".grok" / "auth.json")

    target = "项目 auth.json" if args.into_project else (args.out or args.out_dir or "stdout")
    print(f"🚀 SSO → auth.json: {len(cookies)} 个, target={target}, delay={args.delay}s, threads={args.threads}")

    ok, fail, results = run_concurrent(
        cookies,
        max_workers=args.threads,
        delay=args.delay,
        args_email=args.email,
        into_project=args.into_project,
        out_dir=Path(args.out_dir) if args.out_dir else None,
        out=Path(args.out) if args.out else None,
        merge=args.merge,
    )

    print(f"\n{'=' * 60}\n📊 完成: {ok}/{len(cookies)} 成功, {fail} 失败")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
