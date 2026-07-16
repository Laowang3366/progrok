"""Post-registration account probe and remote import helpers."""
from __future__ import annotations

import time
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit

import httpx

from export_formats import (
    CPA_BASE_URL,
    build_cpa_record,
    build_sub2api_payload,
    cpa_filename,
)

DEFAULT_PROBE_MODEL = "grok-4.5"
PROBE_PERMISSION_RETRY_DELAYS = (5.0, 10.0, 20.0)


def _cpa_api_base_url(value: str) -> str:
    """Accept either the CPA site root or its management.html page URL."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    parsed = urlsplit(raw)
    path = parsed.path.rstrip("/")
    if path.endswith("/management.html"):
        path = path[: -len("/management.html")]
    elif path.endswith("/v0/management"):
        path = path[: -len("/v0/management")]
    return urlunsplit((parsed.scheme, parsed.netloc, path.rstrip("/"), "", ""))


def _error_text(response: httpx.Response) -> str:
    try:
        data = response.json()
        if isinstance(data, dict):
            return str(data.get("message") or data.get("error") or data.get("detail") or "")[:300]
    except Exception:
        pass
    return f"HTTP {response.status_code}"


def _is_transient_permission_error(status_code: int, error: str) -> bool:
    text = str(error or "").lower()
    return status_code == 403 and (
        "access to the chat endpoint is denied" in text
        or "log into console.x.ai and update the permissions" in text
    )


def probe_account(
    record: dict[str, Any],
    model: str = DEFAULT_PROBE_MODEL,
    *,
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    """Run the Grok Build /responses probe used by grokcli-2api."""
    token = str(record.get("access_token") or record.get("key") or "").strip()
    model = str(model or DEFAULT_PROBE_MODEL).strip() or DEFAULT_PROBE_MODEL
    if not token:
        return {"ok": False, "available": False, "model": model, "error": "缺少 access_token"}

    base_url = str(record.get("base_url") or CPA_BASE_URL).rstrip("/")
    if "api.x.ai" in base_url:
        base_url = CPA_BASE_URL.rstrip("/")
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "grok-cli/0.2.93",
        "X-XAI-Token-Auth": "xai-grok-cli",
        "x-grok-client-version": "0.2.93",
        "x-grok-client-identifier": "grok-shell",
    }
    extra_headers = record.get("headers")
    if isinstance(extra_headers, dict):
        for key, value in extra_headers.items():
            if isinstance(key, str) and isinstance(value, str) and key.strip():
                headers[key] = value
    body = {
        "model": model,
        "input": "Reply exactly: OK",
        "max_output_tokens": 8,
    }
    started = time.time()
    owned = client is None
    http = client or httpx.Client(timeout=httpx.Timeout(30.0, connect=10.0))
    try:
        retry_count = 0
        while True:
            response = http.post(f"{base_url}/responses", headers=headers, json=body)
            latency_ms = int((time.time() - started) * 1000)
            if response.status_code < 400:
                return {
                    "ok": True,
                    "available": True,
                    "model": model,
                    "status_code": response.status_code,
                    "latency_ms": latency_ms,
                    "retry_count": retry_count,
                }
            error = _error_text(response)
            if (
                retry_count >= len(PROBE_PERMISSION_RETRY_DELAYS)
                or not _is_transient_permission_error(response.status_code, error)
            ):
                return {
                    "ok": False,
                    "available": False,
                    "model": model,
                    "status_code": response.status_code,
                    "latency_ms": latency_ms,
                    "retry_count": retry_count,
                    "error": error,
                }
            time.sleep(PROBE_PERMISSION_RETRY_DELAYS[retry_count])
            retry_count += 1
    except httpx.HTTPError as exc:
        return {
            "ok": False,
            "available": False,
            "model": model,
            "latency_ms": int((time.time() - started) * 1000),
            "error": f"网络错误：{str(exc)[:220]}",
        }
    finally:
        if owned:
            http.close()


def import_to_cpa(
    record: dict[str, Any],
    *,
    base_url: str,
    api_key: str,
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    base = _cpa_api_base_url(base_url)
    key = str(api_key or "").strip()
    if not base or not key:
        return {"ok": False, "target": "cpa", "error": "CPA 地址或管理密钥未填写"}
    cpa = build_cpa_record(record)
    name = cpa_filename(cpa)
    owned = client is None
    http = client or httpx.Client(timeout=30.0)
    try:
        response = http.post(
            f"{base}/v0/management/auth-files?name={quote(name)}",
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            json=cpa,
        )
        if response.status_code >= 300:
            return {"ok": False, "target": "cpa", "status_code": response.status_code, "error": _error_text(response)}
        return {"ok": True, "target": "cpa", "status_code": response.status_code, "filename": name}
    except httpx.HTTPError as exc:
        return {"ok": False, "target": "cpa", "error": f"网络错误：{str(exc)[:220]}"}
    finally:
        if owned:
            http.close()


def import_to_sub2api(
    record: dict[str, Any],
    *,
    base_url: str,
    api_key: str = "",
    auth_mode: str = "password",
    admin_email: str = "",
    admin_password: str = "",
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    base = str(base_url or "").strip().rstrip("/")
    key = str(api_key or "").strip()
    mode = str(auth_mode or "password").strip().lower()
    email = str(admin_email or "").strip()
    password = str(admin_password or "")
    if not base:
        return {"ok": False, "target": "sub2api", "error": "Sub2API 地址未填写"}
    if mode == "api_key" and not key:
        return {"ok": False, "target": "sub2api", "error": "Sub2API 管理员 API Key 未填写"}
    if mode == "password" and (not email or not password):
        return {"ok": False, "target": "sub2api", "error": "Sub2API 管理员邮箱或密码未填写"}
    if mode not in {"password", "api_key"}:
        return {"ok": False, "target": "sub2api", "error": "不支持的 Sub2API 认证方式"}
    owned = client is None
    http = client or httpx.Client(timeout=30.0)
    try:
        if mode == "password":
            login_response = http.post(
                f"{base}/api/v1/auth/login",
                headers={"Content-Type": "application/json"},
                json={"email": email, "password": password},
            )
            if login_response.status_code >= 300:
                return {
                    "ok": False,
                    "target": "sub2api",
                    "status_code": login_response.status_code,
                    "error": f"Sub2API 登录失败：{_error_text(login_response)}",
                }
            try:
                login_payload = login_response.json()
            except Exception:
                login_payload = {}
            login_data = (
                login_payload.get("data")
                if isinstance(login_payload, dict) and isinstance(login_payload.get("data"), dict)
                else login_payload
            )
            if isinstance(login_data, dict) and login_data.get("requires_2fa"):
                return {
                    "ok": False,
                    "target": "sub2api",
                    "error": "Sub2API 管理员账号启用了二次验证，请改用管理员 API Key",
                }
            access_token = (
                str(login_data.get("access_token") or "").strip()
                if isinstance(login_data, dict)
                else ""
            )
            if not access_token:
                return {
                    "ok": False,
                    "target": "sub2api",
                    "error": "Sub2API 登录响应中没有 access_token",
                }
            auth_headers = {"Authorization": f"Bearer {access_token}"}
        else:
            auth_headers = {"x-api-key": key}
        response = http.post(
            f"{base}/api/v1/admin/accounts/data",
            headers={**auth_headers, "Content-Type": "application/json"},
            json={"data": build_sub2api_payload([record]), "skip_default_group_bind": False},
        )
        if response.status_code >= 300:
            return {"ok": False, "target": "sub2api", "status_code": response.status_code, "error": _error_text(response)}
        try:
            payload = response.json()
        except Exception:
            payload = {}
        result = payload.get("data") if isinstance(payload, dict) and isinstance(payload.get("data"), dict) else payload
        failed = int(result.get("account_failed") or 0) if isinstance(result, dict) else 0
        if failed:
            return {"ok": False, "target": "sub2api", "status_code": response.status_code, "error": f"Sub2API 导入失败账号数：{failed}"}
        created_value = result.get("account_created") if isinstance(result, dict) else None
        created = int(created_value) if created_value is not None else 1
        return {"ok": True, "target": "sub2api", "status_code": response.status_code, "created": created}
    except httpx.HTTPError as exc:
        return {"ok": False, "target": "sub2api", "error": f"网络错误：{str(exc)[:220]}"}
    finally:
        if owned:
            http.close()


def import_account(record: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    target = str(config.get("target") or "sub2api").strip().lower()
    if target == "cpa":
        return import_to_cpa(
            record,
            base_url=str(config.get("cpa_base_url") or ""),
            api_key=str(config.get("cpa_management_key") or ""),
        )
    if target == "sub2api":
        return import_to_sub2api(
            record,
            base_url=str(config.get("sub2api_base_url") or ""),
            api_key=str(config.get("sub2api_api_key") or ""),
            auth_mode=str(config.get("sub2api_auth_mode") or "password"),
            admin_email=str(config.get("sub2api_admin_email") or ""),
            admin_password=str(config.get("sub2api_admin_password") or ""),
        )
    return {"ok": False, "target": target, "error": "不支持的自动导入目标"}
