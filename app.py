from __future__ import annotations

import json
import os
import socket
from io import BytesIO
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from threading import RLock
from typing import Any, Literal
from urllib.parse import unquote, urlparse
from zipfile import ZIP_DEFLATED, ZipFile

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from export_formats import build_cpa_record, build_sub2api_payload, cpa_filename

ROOT = Path(__file__).resolve().parent
CONFIG_FILE = ROOT / "config.json"
STATIC_DIR = ROOT / "static"
SOLVER_PROXY_FILE = ROOT / "turnstile-solver" / "proxies.txt"
_config_lock = RLock()

DEFAULT_CONFIG: dict[str, Any] = {
    "mail_provider": "yyds",
    "mail_api_key": "",
    "mail_base_url": "https://maliapi.215.im",
    "mail_domain": "",
    "mail_prefix": "",
    "mail_expiry_ms": 86400000,
    "captcha_provider": "local",
    "local_solver_url": "http://127.0.0.1:5072",
    "yescaptcha_key": "",
    "proxy": "",
    "proxy_username": "",
    "proxy_password": "",
    "proxy_strategy": "round_robin",
    "count": 1,
    "concurrency": 1,
    "stagger_ms": 1200,
    "probe_delay_sec": 0,
    "probe_model": "grok-4.5",
    "probe_concurrency": 1,
    "probe_stagger_ms": 10000,
    "import_concurrency": 1,
    "import_stagger_ms": 10000,
    "auto_import_enabled": False,
    "auto_import_target": "sub2api",
    "registration_json_format": "cpa",
    "cpa_base_url": "",
    "cpa_management_key": "",
    "sub2api_base_url": "",
    "sub2api_auth_mode": "password",
    "sub2api_admin_email": "",
    "sub2api_admin_password": "",
    "sub2api_api_key": "",
}


def load_config() -> dict[str, Any]:
    with _config_lock:
        data = dict(DEFAULT_CONFIG)
        loaded: dict[str, Any] = {}
        if CONFIG_FILE.exists():
            try:
                loaded = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    data.update({k: v for k, v in loaded.items() if k in DEFAULT_CONFIG})
            except Exception:
                pass
        if str(data.get("mail_provider") or "").lower() != "yyds":
            data["mail_provider"] = "custom"
        # Migrate existing configurations without changing their prior target.
        if "registration_json_format" not in loaded:
            data["registration_json_format"] = data.get("auto_import_target", "cpa")
        if "probe_concurrency" not in loaded:
            data["probe_concurrency"] = data.get("concurrency", 1)
        if "import_concurrency" not in loaded:
            data["import_concurrency"] = data.get("concurrency", 1)
        selected_format = str(data.get("registration_json_format") or "cpa").lower()
        data["registration_json_format"] = selected_format if selected_format in {"cpa", "sub2api"} else "cpa"
        data["auto_import_target"] = data["registration_json_format"]
        return data


def _sync_solver_proxy_file(cfg: dict[str, Any]) -> int:
    from proxy_pool import parse_proxy_pool

    proxies = parse_proxy_pool(
        str(cfg.get("proxy") or ""),
        username=str(cfg.get("proxy_username") or ""),
        password=str(cfg.get("proxy_password") or ""),
        fallback_env=False,
    )
    if not proxies:
        SOLVER_PROXY_FILE.unlink(missing_ok=True)
        return 0
    SOLVER_PROXY_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = SOLVER_PROXY_FILE.with_suffix(".txt.tmp")
    tmp.write_text("\n".join(proxies) + "\n", encoding="utf-8")
    os.replace(tmp, SOLVER_PROXY_FILE)
    return len(proxies)


def save_config(data: dict[str, Any]) -> dict[str, Any]:
    clean = {**DEFAULT_CONFIG, **{k: v for k, v in data.items() if k in DEFAULT_CONFIG}}
    selected_format = str(clean.get("registration_json_format") or "cpa").lower()
    clean["registration_json_format"] = selected_format if selected_format in {"cpa", "sub2api"} else "cpa"
    clean["auto_import_target"] = clean["registration_json_format"]
    with _config_lock:
        tmp = CONFIG_FILE.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(clean, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, CONFIG_FILE)
    apply_environment(clean)
    _sync_solver_proxy_file(clean)
    return clean


def apply_environment(cfg: dict[str, Any]) -> None:
    mapping = {
        "GROK2API_MOEMAIL_API_KEY": cfg.get("mail_api_key", ""),
        "GROK2API_MOEMAIL_BASE_URL": cfg.get("mail_base_url", ""),
        "GROK2API_MOEMAIL_DOMAIN": cfg.get("mail_domain", ""),
        "GROK2API_CAPTCHA_PROVIDER": cfg.get("captcha_provider", "local"),
        "GROK2API_LOCAL_SOLVER_URL": cfg.get("local_solver_url", "http://127.0.0.1:5072"),
        "GROK2API_YESCAPTCHA_KEY": cfg.get("yescaptcha_key", ""),
        "GROK2API_XAI_PROXY": cfg.get("proxy", ""),
        "GROK2API_XAI_PROXY_USERNAME": cfg.get("proxy_username", ""),
        "GROK2API_XAI_PROXY_PASSWORD": cfg.get("proxy_password", ""),
        "GROK2API_XAI_PROXY_STRATEGY": cfg.get("proxy_strategy", "round_robin"),
    }
    for key, value in mapping.items():
        os.environ[key] = str(value or "")


_initial_config = load_config()
apply_environment(_initial_config)
_sync_solver_proxy_file(_initial_config)
import grok_build_adapter as registration  # noqa: E402


class Settings(BaseModel):
    mail_provider: Literal["yyds", "custom"] = "yyds"
    mail_api_key: str = ""
    mail_base_url: str = "https://maliapi.215.im"
    mail_domain: str = ""
    mail_prefix: str = ""
    mail_expiry_ms: int = Field(86400000, ge=60000, le=604800000)
    captcha_provider: Literal["local", "yescaptcha"] = "local"
    local_solver_url: str = "http://127.0.0.1:5072"
    yescaptcha_key: str = ""
    proxy: str = ""
    proxy_username: str = ""
    proxy_password: str = ""
    proxy_strategy: Literal["round_robin", "random", "sticky"] = "round_robin"
    count: int = Field(1, ge=1, le=10000)
    concurrency: int = Field(1, ge=1, le=10)
    stagger_ms: int = Field(1200, ge=0, le=60000)
    probe_delay_sec: int = Field(0, ge=0, le=600)
    probe_model: str = "grok-4.5"
    probe_concurrency: int = Field(1, ge=1, le=10)
    probe_stagger_ms: int = Field(10000, ge=0, le=60000)
    import_concurrency: int = Field(1, ge=1, le=10)
    import_stagger_ms: int = Field(10000, ge=0, le=60000)
    auto_import_enabled: bool = False
    auto_import_target: Literal["cpa", "sub2api"] = "sub2api"
    registration_json_format: Literal["cpa", "sub2api"] = "cpa"
    cpa_base_url: str = ""
    cpa_management_key: str = ""
    sub2api_base_url: str = ""
    sub2api_auth_mode: Literal["password", "api_key"] = "password"
    sub2api_admin_email: str = ""
    sub2api_admin_password: str = ""
    sub2api_api_key: str = ""


class ManualJsonImportRequest(BaseModel):
    payload: Any = None
    payloads: list[Any] = Field(default_factory=list)
    settings: Settings


def _post_registration_config(cfg: dict[str, Any]) -> dict[str, Any]:
    return {
        "model": cfg.get("probe_model") or "grok-4.5",
        "pipeline_concurrency": int(cfg.get("concurrency") or 1),
        "probe_concurrency": int(cfg.get("probe_concurrency") or cfg.get("concurrency") or 1),
        "probe_stagger_ms": int(cfg.get("probe_stagger_ms") or 0),
        "import_concurrency": int(cfg.get("import_concurrency") or cfg.get("concurrency") or 1),
        "import_stagger_ms": int(cfg.get("import_stagger_ms") or 0),
        "auto_import_enabled": bool(cfg.get("auto_import_enabled")),
        "target": cfg.get("auto_import_target") or "sub2api",
        "output_format": cfg.get("registration_json_format") or "cpa",
        "cpa_base_url": cfg.get("cpa_base_url") or "",
        "cpa_management_key": cfg.get("cpa_management_key") or "",
        "sub2api_base_url": cfg.get("sub2api_base_url") or "",
        "sub2api_auth_mode": cfg.get("sub2api_auth_mode") or "password",
        "sub2api_admin_email": cfg.get("sub2api_admin_email") or "",
        "sub2api_admin_password": cfg.get("sub2api_admin_password") or "",
        "sub2api_api_key": cfg.get("sub2api_api_key") or "",
    }


def _manual_import_records(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict) and payload.get("type") == "xai":
        return [payload]
    if isinstance(payload, dict) and payload.get("type") == "sub2api-data":
        records: list[dict[str, Any]] = []
        for account in payload.get("accounts") or []:
            if not isinstance(account, dict):
                continue
            credentials = account.get("credentials") or {}
            extra = account.get("extra") or {}
            if isinstance(credentials, dict) and isinstance(extra, dict):
                records.append({**credentials, **extra})
        return records
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    raise ValueError("仅支持 CPA JSON、Sub2API JSON 或账号 JSON 数组")


app = FastAPI(title="ProGrok 协议注册", version="1.0.0")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
def health() -> dict[str, Any]:
    available = registration.registration_available()
    return {
        "ok": bool(available.get("available")),
        "service": "progrok-registration",
        "registration": available,
        "accounts_dir": str(ROOT / "data" / "accounts"),
    }


@app.get("/api/output-paths")
def output_paths() -> dict[str, Any]:
    paths = [
        {"key": "accounts", "label": "账号文件目录", "path": ROOT / "data" / "accounts"},
        {"key": "auth", "label": "合并 auth.json", "path": ROOT / "data" / "auth.json"},
        {"key": "sso", "label": "SSO 输出目录", "path": ROOT / "grok-build-auth" / "sso_output"},
        {"key": "debug", "label": "注册诊断目录", "path": ROOT / "data" / "register_sso"},
    ]
    return {
        "ok": True,
        "items": [
            {**item, "path": str(item["path"]), "exists": item["path"].exists()}
            for item in paths
        ],
    }


def _stored_auth_by_email() -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    scores: dict[str, int] = {}
    for path in sorted((ROOT / "data" / "accounts").glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        if data.get("type") == "xai":
            candidates = [data]
        elif data.get("type") == "sub2api-data":
            candidates = []
            for account in data.get("accounts") or []:
                if not isinstance(account, dict):
                    continue
                credentials = account.get("credentials") or {}
                extra = account.get("extra") or {}
                if isinstance(credentials, dict) and isinstance(extra, dict):
                    candidates.append({**credentials, **extra})
        else:
            candidates = list(data.values())
        for item in candidates:
            if not isinstance(item, dict):
                continue
            email = str(item.get("email") or "").strip().lower()
            if not email:
                continue
            normalized = {
                **item,
                "access_token": item.get("access_token") or item.get("key") or "",
                "client_id": item.get("client_id") or item.get("oidc_client_id") or "",
                "_source_file": item.get("_source_file") or path.stem,
            }
            score = sum(
                bool(normalized.get(key))
                for key in ("access_token", "refresh_token", "id_token", "sso", "password")
            )
            if score >= scores.get(email, -1):
                result[email] = normalized
                scores[email] = score
    return result


def _download_records(batch_id: str | None = None) -> list[dict[str, Any]]:
    output_dir = ROOT / "grok-build-auth" / "sso_output"
    stored_auth = _stored_auth_by_email()
    records: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for path in sorted(output_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        email = str(data.get("email") or "").strip()
        password = str(data.get("password") or "")
        sso = str(data.get("sso") or "").strip()
        if not sso:
            continue
        identity = (email.lower(), sso)
        if identity in seen:
            continue
        seen.add(identity)
        records.append(
            {
                **stored_auth.get(email.lower(), {}),
                "email": email,
                "password": password,
                "sso": sso,
                "created_at": data.get("created_at"),
            }
        )

    if batch_id:
        batch = registration.get_registration_batch(batch_id)
        if not batch:
            raise HTTPException(status_code=404, detail="批次不存在或服务重启后记录已失效")
        emails = {
            str(item.get("email") or "").strip().lower()
            for item in (batch.get("sessions") or [])
            if str(item.get("status") or "").lower()
            in {"imported", "success", "completed"}
        }
        records = [item for item in records if item["email"].lower() in emails]

    return records


@app.get("/api/download")
def download_accounts(
    export_format: Literal[
        "pure_sso",
        "cookie",
        "email_sso",
        "email_password_sso",
        "json",
        "cpa_json",
        "sub2api_json",
    ] = Query("pure_sso", alias="format"),
    batch_id: str | None = None,
) -> Response:
    records = _download_records(batch_id)
    if not records:
        raise HTTPException(status_code=404, detail="没有可下载的成功注册账号")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if export_format == "json":
        ordinary = [
            {"email": item["email"], "password": item["password"]}
            for item in records
        ]
        content = json.dumps(ordinary, ensure_ascii=False, indent=2) + "\n"
        extension = "json"
        media_type = "application/json; charset=utf-8"
        filename = f"progrok_email_password_{timestamp}.json"
    elif export_format == "sub2api_json":
        content = json.dumps(
            build_sub2api_payload(records), ensure_ascii=False, indent=2
        ) + "\n"
        extension = "json"
        media_type = "application/json; charset=utf-8"
        filename = f"progrok_sub2api_{timestamp}.json"
    elif export_format == "cpa_json":
        cpa_records = [build_cpa_record(item) for item in records]
        if len(cpa_records) == 1:
            content = json.dumps(cpa_records[0], ensure_ascii=False, indent=2) + "\n"
            extension = "json"
            media_type = "application/json; charset=utf-8"
            filename = cpa_filename(cpa_records[0])
        else:
            archive = BytesIO()
            with ZipFile(archive, "w", compression=ZIP_DEFLATED) as zf:
                for index, item in enumerate(cpa_records, start=1):
                    name = cpa_filename(item)
                    if name == "xai-unknown.json":
                        name = f"xai-account-{index}.json"
                    zf.writestr(
                        name,
                        json.dumps(item, ensure_ascii=False, indent=2) + "\n",
                    )
            content = archive.getvalue()
            extension = "zip"
            media_type = "application/zip"
            filename = f"progrok_cpa_{timestamp}.zip"
    else:
        if export_format == "cookie":
            lines = [f"sso={item['sso']}" for item in records]
        elif export_format == "email_sso":
            lines = [f"{item['email']}----{item['sso']}" for item in records]
        elif export_format == "email_password_sso":
            lines = [
                f"{item['email']}:{item['password']}:{item['sso']}" for item in records
            ]
        else:
            lines = [item["sso"] for item in records]
        content = "\n".join(lines) + "\n"
        extension = "txt"
        media_type = "text/plain; charset=utf-8"
        filename = f"progrok_{export_format}_{timestamp}.{extension}"
    return Response(
        content=content if isinstance(content, bytes) else content.encode("utf-8"),
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-ProGrok-Account-Count": str(len(records)),
        },
    )


@app.get("/api/solver/detect")
def detect_solver() -> dict[str, Any]:
    """Scan common loopback ports and return the first healthy local solver."""
    cfg = load_config()
    preferred_ports: list[int] = []
    try:
        parsed = urlparse(str(cfg.get("local_solver_url") or ""))
        if parsed.hostname in {"127.0.0.1", "localhost", "::1"} and parsed.port:
            preferred_ports.append(int(parsed.port))
    except Exception:
        pass

    ports = preferred_ports + [5072] + list(range(5070, 5091))
    ports = list(dict.fromkeys(p for p in ports if 1 <= p <= 65535))

    def probe(port: int) -> dict[str, Any]:
        url = f"http://127.0.0.1:{port}"
        result = registration.probe_local_solver(url, timeout=0.35)
        return {"port": port, "url": url, **result}

    found: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=min(12, len(ports))) as pool:
        futures = [pool.submit(probe, port) for port in ports]
        for future in as_completed(futures):
            try:
                result = future.result()
                if result.get("ready"):
                    found.append(result)
            except Exception:
                pass

    rank = {port: index for index, port in enumerate(ports)}
    found.sort(key=lambda item: rank.get(int(item.get("port") or 0), 9999))
    if found:
        return {"ok": True, "found": True, "url": found[0]["url"], "solver": found[0]}
    return {
        "ok": True,
        "found": False,
        "url": None,
        "error": "未在本机 5070-5090 端口检测到 Turnstile Solver",
    }


def _normalize_detected_proxy(raw: str, *, scheme_hint: str = "") -> dict[str, str] | None:
    value = str(raw or "").strip()
    hint = str(scheme_hint or "").lower()
    if not value:
        return None
    if ";" in value or ("=" in value and "://" not in value):
        choices: dict[str, str] = {}
        for chunk in value.split(";"):
            key, separator, item = chunk.partition("=")
            if separator and item.strip():
                choices[key.strip().lower()] = item.strip()
        for key in ("https", "http", "socks", "socks5"):
            if choices.get(key):
                value = choices[key]
                hint = key
                break
    if "://" not in value:
        scheme = "socks5" if hint.startswith("socks") else "http"
        value = f"{scheme}://{value}"
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError:
        return None
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https", "socks5", "socks5h"}:
        return None
    if not parsed.hostname or not port:
        return None
    host = parsed.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return {
        "proxy": f"{scheme}://{host}:{port}",
        "proxy_username": unquote(parsed.username or ""),
        "proxy_password": unquote(parsed.password or ""),
    }


def _detect_windows_system_proxy() -> tuple[dict[str, str] | None, str]:
    try:
        import winreg

        path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
            try:
                enabled = bool(winreg.QueryValueEx(key, "ProxyEnable")[0])
            except OSError:
                enabled = False
            try:
                server = str(winreg.QueryValueEx(key, "ProxyServer")[0] or "")
            except OSError:
                server = ""
            try:
                pac_url = str(winreg.QueryValueEx(key, "AutoConfigURL")[0] or "")
            except OSError:
                pac_url = ""
        if enabled and server:
            return _normalize_detected_proxy(server), "Windows 系统代理"
        return None, "检测到 PAC 自动代理，无法直接提取固定代理地址" if pac_url else ""
    except (ImportError, OSError):
        return None, ""


def _detect_local_proxy() -> dict[str, Any]:
    detected, note = _detect_windows_system_proxy()
    if detected:
        return {"ok": True, "found": True, "source": "Windows 系统代理", **detected}

    for key in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy"):
        detected = _normalize_detected_proxy(os.environ.get(key, ""))
        if detected:
            return {"ok": True, "found": True, "source": f"环境变量 {key}", **detected}

    common_ports = [(7890, "http"), (7897, "http"), (10809, "http"), (10808, "socks5"), (1080, "socks5")]

    def listening(item: tuple[int, str]) -> tuple[int, str] | None:
        port, scheme = item
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.15):
                return port, scheme
        except OSError:
            return None

    open_ports: list[tuple[int, str]] = []
    with ThreadPoolExecutor(max_workers=len(common_ports)) as pool:
        for result in pool.map(listening, common_ports):
            if result:
                open_ports.append(result)
    if open_ports:
        rank = {port: index for index, (port, _) in enumerate(common_ports)}
        port, scheme = min(open_ports, key=lambda item: rank[item[0]])
        return {
            "ok": True,
            "found": True,
            "source": f"本地监听端口 {port}",
            "proxy": f"{scheme}://127.0.0.1:{port}",
            "proxy_username": "",
            "proxy_password": "",
        }
    return {
        "ok": True,
        "found": False,
        "proxy": None,
        "error": note or "未检测到 Windows 系统代理、代理环境变量或常见本地代理端口",
    }


@app.get("/api/proxy/detect")
def detect_proxy() -> dict[str, Any]:
    return _detect_local_proxy()


@app.get("/api/config")
def get_config() -> dict[str, Any]:
    return load_config()


@app.get("/api/mail/provider-presets")
def mail_provider_presets(response: Response) -> dict[str, Any]:
    response.headers["Cache-Control"] = "no-store"
    return {
        "providers": {
            "yyds": {
                "available": True,
                "mail_base_url": "https://maliapi.215.im",
                "mail_api_key": "",
                "mail_domain": "",
            },
            "custom": {
                "available": True,
                "mail_base_url": "",
                "mail_api_key": "",
                "mail_domain": "",
            },
        }
    }


@app.put("/api/config")
def put_config(settings: Settings) -> dict[str, Any]:
    return {"ok": True, "config": save_config(settings.model_dump())}


@app.post("/api/register")
def start_register(settings: Settings | None = None, paused: bool = False) -> dict[str, Any]:
    cfg = settings.model_dump() if settings else load_config()
    if settings is not None:
        persisted = load_config()
        persisted["count"] = cfg["count"]
        persisted["concurrency"] = cfg["concurrency"]
        persisted["probe_concurrency"] = cfg["probe_concurrency"]
        persisted["import_concurrency"] = cfg["import_concurrency"]
        save_config(persisted)
    selected_format = str(cfg.get("registration_json_format") or cfg.get("auto_import_target") or "cpa").lower()
    cfg["registration_json_format"] = selected_format if selected_format in {"cpa", "sub2api"} else "cpa"
    cfg["auto_import_target"] = cfg["registration_json_format"]
    # Starting a task persists only its batch size controls. Mailbox credentials
    # still require the explicit "保存配置" action.
    apply_environment(cfg)
    _sync_solver_proxy_file(cfg)
    result = registration.start_registration(
        captcha_provider=cfg["captcha_provider"],
        local_solver_url=cfg["local_solver_url"],
        yescaptcha_key=cfg["yescaptcha_key"],
        proxy=cfg["proxy"],
        proxy_username=cfg["proxy_username"],
        proxy_password=cfg["proxy_password"],
        proxy_strategy=cfg["proxy_strategy"],
        moemail_api_key=cfg["mail_api_key"],
        moemail_base_url=cfg["mail_base_url"],
        prefix=cfg["mail_prefix"],
        domain=cfg["mail_domain"],
        expiry_ms=cfg["mail_expiry_ms"],
        mail_provider=cfg["mail_provider"],
        count=cfg["count"],
        concurrency=cfg["concurrency"],
        stagger_ms=cfg["stagger_ms"],
        probe_delay_sec=cfg["probe_delay_sec"],
        post_registration=_post_registration_config(cfg),
        start_paused=paused,
    )
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result)
    return result


@app.get("/api/sessions")
def sessions() -> dict[str, Any]:
    return registration.list_registration_sessions()


@app.post("/api/sessions/reset")
def reset_sessions() -> dict[str, Any]:
    result = registration.reset_registration_monitor()
    if not result.get("ok"):
        raise HTTPException(status_code=409, detail=result)
    return result


@app.get("/api/sessions/{session_id}")
def session(session_id: str) -> dict[str, Any]:
    result = registration.get_registration_session(session_id)
    if result is None:
        raise HTTPException(status_code=404, detail="session not found")
    return result


@app.get("/api/batches/{batch_id}")
def batch(batch_id: str) -> dict[str, Any]:
    result = registration.get_registration_batch(batch_id)
    if result is None:
        raise HTTPException(status_code=404, detail="batch not found")
    return result


@app.post("/api/sessions/{session_id}/stop")
def stop_session(session_id: str) -> dict[str, Any]:
    return registration.stop_registration_session(session_id)


@app.post("/api/batches/{batch_id}/stop")
def stop_batch(batch_id: str) -> dict[str, Any]:
    return registration.stop_registration_batch(batch_id)


@app.post("/api/batches/{batch_id}/pause")
def pause_batch(batch_id: str) -> dict[str, Any]:
    result = registration.pause_registration_batch(batch_id)
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result)
    return result


@app.post("/api/batches/{batch_id}/resume")
def resume_batch(batch_id: str) -> dict[str, Any]:
    result = registration.resume_registration_batch(batch_id, force=True)
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result)
    return result


@app.post("/api/sessions/{session_id}/retry-probe")
def retry_session_probe(session_id: str) -> dict[str, Any]:
    result = registration.retry_registration_probe(
        session_id, _post_registration_config(load_config())
    )
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result)
    return result


@app.post("/api/batches/{batch_id}/retry-probe")
def retry_batch_probe(batch_id: str) -> dict[str, Any]:
    result = registration.retry_registration_batch_probe(
        batch_id, _post_registration_config(load_config())
    )
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result)
    return result


@app.post("/api/sessions/{session_id}/retry-import")
def retry_session_import(session_id: str) -> dict[str, Any]:
    result = registration.retry_registration_import(
        session_id, _post_registration_config(load_config())
    )
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result)
    return result


@app.post("/api/batches/{batch_id}/retry-import")
def retry_batch_import(batch_id: str) -> dict[str, Any]:
    result = registration.retry_registration_batch_import(
        batch_id, _post_registration_config(load_config())
    )
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result)
    return result


@app.post("/api/import/json")
def manual_json_import(request: ManualJsonImportRequest) -> dict[str, Any]:
    try:
        documents = list(request.payloads)
        if request.payload is not None:
            documents.append(request.payload)
        records: list[dict[str, Any]] = []
        for document in documents:
            records.extend(_manual_import_records(document))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not records:
        raise HTTPException(status_code=400, detail="JSON 中没有可导入账号")
    cfg = request.settings.model_dump()
    selected = str(
        cfg.get("registration_json_format") or cfg.get("auto_import_target") or "cpa"
    ).lower()
    cfg["auto_import_target"] = selected if selected in {"cpa", "sub2api"} else "cpa"
    pipeline = _post_registration_config(cfg)
    from account_pipeline import import_account

    results: list[dict[str, Any]] = []
    for record in records:
        registration.wait_pipeline_stagger("import", pipeline.get("import_stagger_ms") or 0)
        response = import_account(record, pipeline)
        results.append(
            {
                "ok": bool(response.get("ok")),
                "status_code": response.get("status_code"),
                "error": str(response.get("error") or "")[:220] or None,
            }
        )
    imported = sum(1 for item in results if item["ok"])
    failed = len(results) - imported
    return {
        "ok": failed == 0,
        "target": pipeline["target"],
        "count": len(results),
        "imported": imported,
        "failed": failed,
        "errors": [item["error"] for item in results if item.get("error")][:10],
    }
