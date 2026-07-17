"""Adapter: grok-build-auth -> grokcli-2api account pool.

Drives the vendored ``grok-build-auth/xconsole_client`` protocol client to:

1. register an x.ai account with MoeMail + YesCaptcha
2. extract SSO/session cookies
3. convert SSO via sso_to_auth_json into a local auth.json entry
4. import that entry into the multi-account pool

Import of ``xconsole_client`` is deferred so the main API can start even when
optional deps are missing. Registration endpoints then return a clear error
instead of crashing process startup.

``grok-build-auth`` is vendored in-tree (not a git submodule).
Legacy browser (DrissionPage) and grpc-session registration engines were removed.
"""
from __future__ import annotations

import json
import os
import secrets
import string
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from performance_tuning import AdaptiveRegistrationTuner, machine_profile, system_sample

BACKEND_DIR = Path(__file__).resolve().parent
APP_DIR = BACKEND_DIR.parent
RUNTIME_DATA_DIR = APP_DIR / "runtime" / "data"
GBA = APP_DIR / "vendor" / "grok-build-auth"
ADAPTER_BUILD = "2026-07-15-import-success-only-8"
# Newly registered accounts often need a short settle window before probe.
REGISTER_PROBE_DELAY_SEC = float(
    os.environ.get("GROK2API_REG_PROBE_DELAY_SEC", "30") or 30
)

YESCAPTCHA_KEY = (
    os.environ.get("GROK2API_YESCAPTCHA_KEY")
    or os.environ.get("YESCAPTCHA_API_KEY")
    or ""
).strip()

CAPTCHA_PROVIDER = (
    os.environ.get("GROK2API_CAPTCHA_PROVIDER")
    or os.environ.get("CAPTCHA_PROVIDER")
    or "local"
).strip().lower()
if CAPTCHA_PROVIDER not in {"local", "yescaptcha"}:
    CAPTCHA_PROVIDER = "local"

LOCAL_SOLVER_URL = (
    os.environ.get("GROK2API_LOCAL_SOLVER_URL")
    or os.environ.get("LOCAL_SOLVER_URL")
    or os.environ.get("GROK2API_YESCAPTCHA_ENDPOINT")
    or os.environ.get("YESCAPTCHA_ENDPOINT")
    or "http://127.0.0.1:5072"
).strip().rstrip("/")

# Hard cap for multi-thread registration concurrency only (YesCaptcha + xAI rate limits).
# Batch count is intentionally uncapped — only concurrency bounds parallelism.
MAX_CONCURRENCY = int(os.environ.get("GROK2API_REG_MAX_CONCURRENCY", "10") or 10)
DEFAULT_CONCURRENCY = int(os.environ.get("GROK2API_REG_CONCURRENCY", "3") or 3)

# When captcha_provider=local, registration must wait for the inline Turnstile
# Solver HTTP to answer before spawning workers. Prevents "already running but
# captcha always fails because solver is still booting / restarting".
LOCAL_SOLVER_WAIT_SEC = float(
    os.environ.get("GROK2API_LOCAL_SOLVER_WAIT_SEC", "120") or 120
)
LOCAL_SOLVER_POLL_SEC = float(
    os.environ.get("GROK2API_LOCAL_SOLVER_POLL_SEC", "1.0") or 1.0
)

# --------------------------------------------------------------------------- #
# session state
# --------------------------------------------------------------------------- #
_sessions: dict[str, dict[str, Any]] = {}
_batches: dict[str, dict[str, Any]] = {}
_lock = threading.RLock()
# batch_id -> True while a local ThreadPool spawner is alive in THIS process.
_active_batch_runners: dict[str, bool] = {}
# Keep local captcha fan-out aligned with the Solver browser pool. A bounded
# semaphore prevents registration workers from overfilling the available slots.
try:
    _LOCAL_CAPTCHA_CONCURRENCY = max(
        1,
        min(
            10,
            int(os.environ.get("GROK2API_LOCAL_CAPTCHA_CONCURRENCY", "3") or 3),
        ),
    )
except (TypeError, ValueError):
    _LOCAL_CAPTCHA_CONCURRENCY = 3
_local_captcha_slots = threading.BoundedSemaphore(_LOCAL_CAPTCHA_CONCURRENCY)
_pipeline_stagger_lock = threading.RLock()
_pipeline_next_allowed = {"probe": 0.0, "import": 0.0}
_pipeline_queue_lock = threading.RLock()
_pipeline_queues: dict[str, dict[str, Any]] = {}
PROBE_RECHECK_DELAYS = (30.0, 120.0, 300.0)
_probe_slots_lock = threading.RLock()
_probe_slots: dict[tuple[str, int], threading.BoundedSemaphore] = {}
# Cross-batch in-flight registration jobs (3 open batches * 8 workers used to
# stampede local Camoufox + xAI device-flow). Cap total concurrent registrations.
try:
    _GLOBAL_REG_INFLIGHT_MAX = max(
        1,
        min(
            32,
            int(os.environ.get("GROK2API_REG_GLOBAL_INFLIGHT", "6") or 6),
        ),
    )
except (TypeError, ValueError):
    _GLOBAL_REG_INFLIGHT_MAX = 6
_global_reg_inflight = threading.Semaphore(_GLOBAL_REG_INFLIGHT_MAX)
# Soft rate-limit signal: after device-flow / captcha storms, temporarily reduce
# new job admission without killing already-running workers.
_reg_soft_pause_until = 0.0
_reg_soft_pause_lock = threading.Lock()
_xconsole_ready = False
_xconsole_error: str | None = None


def _note_reg_pressure(reason: str = "", *, pause_sec: float | None = None) -> None:
    """Backoff new admissions briefly when upstream rate-limits hit."""
    global _reg_soft_pause_until
    try:
        sec = float(
            pause_sec
            if pause_sec is not None
            else (os.environ.get("GROK2API_REG_SOFT_PAUSE_SEC", "8") or 8)
        )
    except (TypeError, ValueError):
        sec = 8.0
    sec = max(1.0, min(60.0, sec))
    with _reg_soft_pause_lock:
        _reg_soft_pause_until = max(_reg_soft_pause_until, time.time() + sec)
    if reason:
        print(f"[registration] soft-pause {sec:.0f}s ({reason})")


def _wait_reg_admission(*, check_cancel=None) -> None:
    """Block until global inflight slot is free and soft-pause window ends."""
    while True:
        if check_cancel is not None:
            try:
                check_cancel()
            except Exception:
                raise
        with _reg_soft_pause_lock:
            wait = _reg_soft_pause_until - time.time()
        if wait > 0:
            time.sleep(min(1.0, wait))
            continue
        # non-blocking try then short sleep to stay cancel-friendly
        if _global_reg_inflight.acquire(blocking=False):
            return
        time.sleep(0.15)


def _release_reg_admission() -> None:
    try:
        _global_reg_inflight.release()
    except Exception:
        pass


def wait_pipeline_stagger(phase: str, delay_ms: int | float | None) -> None:
    """Space probe/import request starts across concurrent registration workers."""
    name = "import" if str(phase).lower() == "import" else "probe"
    try:
        interval = max(0.0, min(60.0, float(delay_ms or 0) / 1000.0))
    except (TypeError, ValueError):
        interval = 0.0
    if interval <= 0:
        return
    with _pipeline_stagger_lock:
        now = time.monotonic()
        scheduled = max(now, float(_pipeline_next_allowed.get(name) or 0.0))
        _pipeline_next_allowed[name] = scheduled + interval
    wait = scheduled - time.monotonic()
    if wait > 0:
        time.sleep(wait)

REG_BATCH_RUNNER_LOCK_TTL = int(os.environ.get("GROK2API_REG_RUNNER_LOCK_TTL", "90") or 90)
def _now() -> float:
    return time.time()


def _reg_redis() -> bool:
    try:
        from store.redis_client import redis_enabled

        return redis_enabled()
    except Exception:
        return False


def _batch_runner_lock_key(batch_id: str) -> str:
    try:
        from store.redis_client import key

        return key("reg", "runner", batch_id)
    except Exception:
        return f"g2a:reg:runner:{batch_id}"


def _try_acquire_batch_runner(batch_id: str) -> tuple[bool, str | None]:
    """Claim exclusive spawner ownership for a batch (cross-worker).

    Returns (acquired, token). Local-process claim always required; Redis NX
    is used when available so multi-worker won't double-spawn.
    """
    bid = str(batch_id or "").strip()
    if not bid:
        return False, None
    with _lock:
        if _active_batch_runners.get(bid):
            return False, None
        _active_batch_runners[bid] = True
    token = f"{uuid.uuid4().hex}|{os.getpid()}|{_now():.0f}"
    if _reg_redis():
        try:
            from store.redis_client import set_nx_ex, worker_id

            token = f"{worker_id()}|{os.getpid()}|{uuid.uuid4().hex[:10]}"
            ok = set_nx_ex(_batch_runner_lock_key(bid), token, REG_BATCH_RUNNER_LOCK_TTL)
            if not ok:
                with _lock:
                    _active_batch_runners.pop(bid, None)
                return False, None
        except Exception:
            # Fall through to local-only claim.
            pass
    return True, token


def _renew_batch_runner(batch_id: str, token: str | None) -> None:
    if not token or not _reg_redis():
        return
    try:
        from store.redis_client import renew_if_owner

        renew_if_owner(_batch_runner_lock_key(batch_id), token, REG_BATCH_RUNNER_LOCK_TTL)
    except Exception:
        pass


def _release_batch_runner(batch_id: str, token: str | None) -> None:
    bid = str(batch_id or "").strip()
    with _lock:
        _active_batch_runners.pop(bid, None)
    if token and _reg_redis():
        try:
            from store.redis_client import compare_and_delete

            compare_and_delete(_batch_runner_lock_key(bid), token)
        except Exception:
            pass


def _snapshot_reg_config(
    *,
    captcha_provider: str,
    yescaptcha_key: str,
    proxy: str,
    moemail_api_key: str | None,
    moemail_base_url: str | None,
    prefix: str | None,
    domain: str | None,
    expiry_ms: int | None,
    concurrency: int,
    stagger_ms: int,
    mail_provider: str | None = None,
    post_registration: dict[str, Any] | None = None,
    auto_tune_enabled: bool = False,
) -> dict[str, Any]:
    """Config snapshot kept with the in-memory/Redis batch while it is running."""
    return {
        "captcha_provider": captcha_provider,
        "yescaptcha_key": yescaptcha_key if captcha_provider == "yescaptcha" else "",
        "proxy": proxy or "",
        "moemail_api_key": moemail_api_key or "",
        "moemail_base_url": moemail_base_url or "",
        "prefix": prefix or "",
        "domain": domain or "",
        "expiry_ms": expiry_ms,
        "concurrency": concurrency,
        "stagger_ms": stagger_ms,
        "local_solver_url": "http://127.0.0.1:5072",
        "mail_provider": (mail_provider or "moemail").strip().lower() or "moemail",
        "post_registration": dict(post_registration or {}),
        "auto_tune_enabled": bool(auto_tune_enabled),
    }


class _RegCancelled(Exception):
    """Cooperative cancel for in-flight registration workers."""


_TERMINAL_STATUSES = frozenset(
    {
        "imported",
        "success",
        "completed",
        "error",
        "failed",
        "expired",
        "protocol_error",
        "protocol_blocked",
        "cancelled",
        "stopped",
    }
)

_REGISTRATION_STAGE_BY_STATUS = {
    "waiting_solver": "captcha",
    "solving_turnstile": "captcha",
    "waiting_email": "email",
    "registering": "account",
    "creating_account": "account",
    "fetching_sso": "auth",
    "importing": "auth",
}


def _is_cancel_status(status: str | None) -> bool:
    return str(status or "").lower() in ("cancelled", "stopped", "stopping")


def _session_cancel_requested(sess: dict[str, Any] | None) -> bool:
    if not isinstance(sess, dict):
        return False
    if sess.get("cancel_requested"):
        return True
    return _is_cancel_status(sess.get("status"))


def _mirror_reg_sess(sid: str, sess: dict[str, Any] | None) -> None:
    if not _reg_redis() or not sid:
        return
    try:
        from store import sessions_redis

        if sess is None:
            sessions_redis.reg_sess_delete(sid)
        else:
            # Always strip process-local fields before Redis write.
            payload = {
                k: v
                for k, v in sess.items()
                if isinstance(k, str) and not k.startswith("_") and not callable(v)
            }
            sessions_redis.reg_sess_put(sid, payload)
    except Exception:
        pass


def _mirror_reg_batch(batch_id: str, batch: dict[str, Any] | None) -> None:
    if not _reg_redis() or not batch_id or batch is None:
        return
    try:
        from store import sessions_redis

        sessions_redis.reg_batch_put(batch_id, batch)
    except Exception:
        pass


def _record_register_task(
    *,
    task_id: str | None,
    summary: str,
    status: str,
    ok: bool | None = None,
    progress_done: int = 0,
    progress_total: int = 0,
    finished: bool = True,
    detail: dict[str, Any] | None = None,
) -> None:
    """Best-effort write into admin「任务日志」for protocol registration."""
    tid = str(task_id or "").strip()
    if not tid:
        return
    try:
        import task_log

        task_log.record(
            "register",
            task_id=tid,
            summary=str(summary or f"协议注册 {tid}")[:500],
            status=str(status or "done"),
            ok=ok,
            progress_done=int(progress_done or 0),
            progress_total=int(progress_total or 0),
            finished=bool(finished),
            detail=detail if isinstance(detail, dict) else {},
        )
    except Exception:
        # Never break registration workers because of logging.
        pass


def _session_task_log_payload(sess: dict[str, Any] | None) -> dict[str, Any]:
    s = sess if isinstance(sess, dict) else {}
    st = str(s.get("status") or "done").lower() or "done"
    ok: bool | None
    if st in ("imported", "success", "completed", "done"):
        ok = True
    elif st in ("error", "failed", "expired", "protocol_error", "protocol_blocked"):
        ok = False
    elif st in ("cancelled", "stopped"):
        ok = False
    else:
        ok = None
    email = str(s.get("email") or "").strip()
    summary = str(s.get("message") or "").strip()
    if not summary:
        summary = f"协议注册 {email or s.get('id') or ''}".strip()
    return {
        "task_id": str(s.get("id") or ""),
        "summary": summary,
        "status": st,
        "ok": ok,
        "progress_done": 1 if st in _TERMINAL_STATUSES else 0,
        "progress_total": 1,
        "finished": st in _TERMINAL_STATUSES,
        "detail": {
            "session_id": s.get("id"),
            "batch_id": s.get("batch_id"),
            "email": email or None,
            "status": st,
            "error": s.get("error"),
            "imported_account_ids": list(s.get("imported_account_ids") or [])[:20],
            "adapter_build": s.get("adapter_build") or ADAPTER_BUILD,
        },
    }


def _load_reg_sess(sid: str) -> dict[str, Any] | None:
    with _lock:
        local = _sessions.get(sid)
        if local is not None:
            return local
    if not _reg_redis():
        return None
    try:
        from store import sessions_redis

        remote = sessions_redis.reg_sess_get(sid)
        if remote:
            with _lock:
                _sessions.setdefault(sid, remote)
            return remote
    except Exception:
        pass
    return None


def _load_reg_batch(batch_id: str) -> dict[str, Any] | None:
    with _lock:
        local = _batches.get(batch_id)
        if local is not None:
            return local
    if not _reg_redis():
        return None
    try:
        from store import sessions_redis

        remote = sessions_redis.reg_batch_get(batch_id)
        if remote:
            with _lock:
                _batches.setdefault(batch_id, remote)
            return remote
    except Exception:
        pass
    return None


def _pipeline_group(sess: dict[str, Any]) -> str:
    return str(sess.get("batch_id") or f"session-{sess.get('id') or uuid.uuid4().hex}")


def _probe_group_slots(group: str, limit: int) -> threading.BoundedSemaphore:
    key = (str(group or "probe"), max(1, int(limit)))
    with _probe_slots_lock:
        slots = _probe_slots.get(key)
        if slots is None:
            slots = threading.BoundedSemaphore(key[1])
            _probe_slots[key] = slots
        return slots


def _append_session_event(
    sess: dict[str, Any], status: str, message: str, *, at: float | None = None
) -> None:
    events = [dict(item) for item in (sess.get("events") or []) if isinstance(item, dict)]
    event = {
        "at": float(at or _now()),
        "status": str(status or "unknown"),
        "message": str(message or ""),
    }
    if events and all(events[-1].get(key) == event[key] for key in ("status", "message")):
        return
    events.append(event)
    sess["events"] = events[-60:]


def _set_pipeline_session_state(
    sid: str, status: str, message: str, *, phase: str, position: int, limit: int
) -> None:
    with _lock:
        current = _sessions.get(sid) or _load_reg_sess(sid)
        if not current:
            return
        current = dict(current)
        queue_state = {
            "phase": phase,
            "position": max(0, int(position)),
            "concurrency": max(1, int(limit)),
        }
        if phase == "probe":
            probe = dict(current.get("probe") or {})
            probe.update(
                {
                    "state": "running" if status == "probing" else "queued",
                    "queued": status != "probing",
                    "position": queue_state["position"],
                    "concurrency": queue_state["concurrency"],
                }
            )
            current["probe"] = probe
            current["probe_queue"] = queue_state
        else:
            current["status"] = status
            current["message"] = message
            current["pipeline_queue"] = queue_state
        current["updated_at"] = _now()
        _append_session_event(current, status, message, at=current["updated_at"])
        _sessions[sid] = current
        _mirror_reg_sess(sid, current)


def _refresh_pipeline_positions(state: dict[str, Any]) -> None:
    phase = str(state.get("phase") or "probe")
    limit = int(state.get("limit") or 1)
    status = "import_queued" if phase == "import" else "probe_queued"
    label = "导入" if phase == "import" else "测活"
    for position, sid in enumerate(list(state.get("pending") or []), start=1):
        _set_pipeline_session_state(
            str(sid),
            status,
            f"已进入{label}缓存队列，当前排队第 {position} 位",
            phase=phase,
            position=position,
            limit=limit,
        )


def _close_pipeline_phase(group: str, phase: str) -> None:
    key = f"{group}:{phase}"
    with _pipeline_queue_lock:
        state = _pipeline_queues.get(key)
        if state is not None:
            state["producer_closed"] = True


def _finish_pipeline_without_import(sid: str, config: dict[str, Any]) -> None:
    sess = _load_reg_sess(sid) or {}
    target = str(config.get("target") or "sub2api").lower()
    auto_import = {
        "enabled": False,
        "target": target,
        "ok": None,
        "skipped": True,
    }
    with _lock:
        current = _sessions.get(sid) or dict(sess)
        current["auto_import"] = auto_import
        current["status"] = "imported"
        current["message"] = "本地账号已保存；自动导入未开启；自动测活独立执行"
        current["pipeline_queue"] = {
            "phase": "done",
            "position": 0,
            "concurrency": int(config.get("pipeline_concurrency") or 1),
        }
        current["updated_at"] = _now()
        _append_session_event(
            current, current["status"], current["message"], at=current["updated_at"]
        )
        _sessions[sid] = current
        _mirror_reg_sess(sid, current)


def _mark_pipeline_cancelled(sid: str) -> None:
    with _lock:
        current = _sessions.get(sid) or _load_reg_sess(sid)
        if not current:
            return
        current = dict(current)
        current["status"] = "cancelled"
        current["message"] = "队列任务已取消"
        current["error"] = "cancelled"
        current["cancel_requested"] = True
        current["updated_at"] = _now()
        _append_session_event(
            current, current["status"], current["message"], at=current["updated_at"]
        )
        _sessions[sid] = current
        _mirror_reg_sess(sid, current)


def _run_probe_wave(group: str, session_ids: list[str], limit: int) -> None:
    from concurrent.futures import ThreadPoolExecutor, as_completed

    for sid in session_ids:
        _set_pipeline_session_state(
            sid,
            "probing",
            f"本批 {len(session_ids)} 个账号正在测活，按错峰时间依次发起",
            phase="probe",
            position=0,
            limit=limit,
        )

    slots = _probe_group_slots(group, limit)

    def run_one(sid: str) -> dict[str, Any]:
        with slots:
            sess = _load_reg_sess(sid) or {}
            if _session_cancel_requested(sess):
                _mark_pipeline_cancelled(sid)
                return {"ok": False, "session_id": sid, "cancelled": True}
            config = dict(sess.get("_post_registration") or {})
            return _retry_probe_now(sid, config, manual_retry=False)

    with ThreadPoolExecutor(max_workers=limit, thread_name_prefix="gba-probe-wave") as pool:
        futures = {pool.submit(run_one, sid): sid for sid in session_ids}
        for future in as_completed(futures):
            sid = futures[future]
            try:
                future.result()
            except Exception as exc:  # noqa: BLE001
                with _lock:
                    current = _sessions.get(sid) or {}
                    current["probe"] = {
                        "count": 1,
                        "ok": 0,
                        "fail": 1,
                        "state": "complete",
                        "queued": False,
                        "position": 0,
                        "results": [
                            {"account_id": None, "ok": False, "error": str(exc)[:180]}
                        ],
                    }
                    current["updated_at"] = _now()
                    _append_session_event(
                        current,
                        "probe_complete",
                        f"队列测活异常结束：{str(exc)[:180]}",
                        at=current["updated_at"],
                    )
                    _sessions[sid] = current
                    _mirror_reg_sess(sid, current)

def _run_import_wave(group: str, session_ids: list[str], limit: int) -> None:
    from concurrent.futures import ThreadPoolExecutor, as_completed

    for sid in session_ids:
        _set_pipeline_session_state(
            sid,
            "auto_importing",
            f"本批 {len(session_ids)} 个账号正在导入，按错峰时间依次发起",
            phase="import",
            position=0,
            limit=limit,
        )

    def run_one(sid: str) -> dict[str, Any]:
        sess = _load_reg_sess(sid) or {}
        if _session_cancel_requested(sess):
            _mark_pipeline_cancelled(sid)
            return {"ok": False, "session_id": sid, "cancelled": True}
        config = dict(sess.get("_post_registration") or {})
        return _retry_import_now(sid, config, manual_retry=False)

    with ThreadPoolExecutor(max_workers=limit, thread_name_prefix="gba-import-wave") as pool:
        futures = {pool.submit(run_one, sid): sid for sid in session_ids}
        for future in as_completed(futures):
            sid = futures[future]
            try:
                future.result()
            except Exception as exc:  # noqa: BLE001
                sess = _load_reg_sess(sid) or {}
                config = dict(sess.get("_post_registration") or {})
                target = str(config.get("target") or "sub2api").lower()
                with _lock:
                    current = _sessions.get(sid) or dict(sess)
                    current["auto_import"] = {
                        "enabled": True,
                        "target": target,
                        "ok": False,
                        "skipped": False,
                        "count": 1,
                        "imported": 0,
                        "failed": 1,
                        "error": str(exc)[:220],
                    }
                    current["status"] = "imported"
                    current["message"] = "队列导入异常结束：成功 0，失败 1"
                    current["pipeline_queue"] = {
                        "phase": "done",
                        "position": 0,
                        "concurrency": int(config.get("pipeline_concurrency") or limit),
                    }
                    current["updated_at"] = _now()
                    _sessions[sid] = current
                    _mirror_reg_sess(sid, current)


def _pipeline_dispatch_loop(key: str) -> None:
    while True:
        wave: list[str] = []
        phase = "probe"
        group = ""
        limit = 1
        with _pipeline_queue_lock:
            state = _pipeline_queues.get(key)
            if state is None:
                return
            pending = state.get("pending") or []
            phase = str(state.get("phase") or "probe")
            group = str(state.get("group") or "")
            limit = max(1, int(state.get("limit") or 1))
            closed = bool(state.get("producer_closed"))
            if pending and (len(pending) >= limit or closed):
                wave = [str(pending.pop(0)) for _ in range(min(limit, len(pending)))]
                state["in_wave"] = True
                _refresh_pipeline_positions(state)
            elif not pending and closed:
                _pipeline_queues.pop(key, None)
                return
            else:
                state["in_wave"] = False
        if not wave:
            time.sleep(0.2)
            continue
        if phase == "import":
            _run_import_wave(group, wave, limit)
        else:
            _run_probe_wave(group, wave, limit)
        with _pipeline_queue_lock:
            state = _pipeline_queues.get(key)
            if state is not None:
                state["in_wave"] = False


def _enqueue_pipeline_phase(sid: str, phase: str = "probe") -> None:
    sess = _load_reg_sess(sid) or {}
    if not sess:
        return
    name = "import" if str(phase).lower() == "import" else "probe"
    if name == "import":
        status = str(sess.get("status") or "").lower()
        if status in {
            "error",
            "failed",
            "protocol_error",
            "protocol_blocked",
            "cancelled",
            "stopped",
        }:
            return
        if not (sess.get("imported_account_ids") or []):
            return
    config = dict(sess.get("_post_registration") or {})
    group = _pipeline_group(sess)
    concurrency_key = "import_concurrency" if name == "import" else "probe_concurrency"
    limit = max(
        1,
        min(
            MAX_CONCURRENCY,
            int(
                config.get(concurrency_key)
                or config.get("pipeline_concurrency")
                or (_load_reg_batch(group) or {}).get("concurrency")
                or 1
            ),
        ),
    )
    key = f"{group}:{name}"
    start_thread = False
    with _pipeline_queue_lock:
        state = _pipeline_queues.get(key)
        if state is None:
            state = {
                "group": group,
                "phase": name,
                "limit": limit,
                "pending": [],
                "producer_closed": not bool(sess.get("batch_id")),
                "in_wave": False,
            }
            _pipeline_queues[key] = state
            start_thread = True
        state["limit"] = limit
        if sid not in state["pending"]:
            state["pending"].append(sid)
        _refresh_pipeline_positions(state)
    if name == "import":
        target = str(config.get("target") or "sub2api").lower()
        with _lock:
            current = _sessions.get(sid) or dict(sess)
            current["auto_import"] = {
                "enabled": True,
                "target": target,
                "ok": None,
                "skipped": False,
                "queued": True,
            }
            current["updated_at"] = _now()
            _sessions[sid] = current
            _mirror_reg_sess(sid, current)
    if start_thread:
        threading.Thread(
            target=_pipeline_dispatch_loop,
            args=(key,),
            daemon=True,
            name=f"gba-{name}-queue-{group[-8:]}",
        ).start()


def _clean_old_sessions() -> None:
    cutoff = _now() - 6 * 3600
    for sid in list(_sessions.keys()):
        sess = _sessions.get(sid) or {}
        if float(sess.get("updated_at") or 0) < cutoff:
            _sessions.pop(sid, None)
            _mirror_reg_sess(sid, None)


def _compact_session(sess: dict[str, Any]) -> dict[str, Any]:
    out = dict(sess)
    # Process-local helpers such as _receiver/_client are not JSON serializable
    # and must never leak into API polling responses while a job is running.
    for key in list(out):
        if isinstance(key, str) and key.startswith("_"):
            out.pop(key, None)
    out.pop("password", None)
    out.pop("yescaptcha_key", None)
    # Prefer explicit imported ids; fall back to auth_json summary for UI/logs.
    imported_ids = list(out.get("imported_account_ids") or [])
    imported_accounts = list(out.get("imported_accounts") or [])
    aj = out.get("auth_json")
    if isinstance(aj, dict):
        rows = [x for x in (aj.get("imported") or []) if isinstance(x, dict)]
        out["auth_json_count"] = len(rows)
        if not imported_ids:
            imported_ids = [str(x.get("id")) for x in rows if x.get("id")]
        if not imported_accounts:
            imported_accounts = [
                {"id": x.get("id"), "email": x.get("email")}
                for x in rows
                if x.get("id") or x.get("email")
            ]
    elif aj is not None:
        try:
            out["auth_json_count"] = len(aj)  # type: ignore[arg-type]
        except Exception:
            out["auth_json_count"] = 0
    if imported_ids:
        out["imported_account_ids"] = imported_ids
    if imported_accounts:
        out["imported_accounts"] = imported_accounts
    # Drop full auth payload from list/poll responses (secrets).
    out.pop("auth_json", None)
    return out


def ensure_xconsole() -> None:
    """Ensure vendored grok-build-auth/xconsole_client is importable.

    Raises RuntimeError with actionable message when unavailable.
    Safe to call multiple times.
    """
    global _xconsole_ready, _xconsole_error
    if _xconsole_ready:
        return
    if _xconsole_error:
        raise RuntimeError(_xconsole_error)

    if not GBA.is_dir():
        _xconsole_error = (
            "grok-build-auth 目录不存在。请确认仓库完整检出，"
            "或重新 clone 本项目。"
        )
        raise RuntimeError(_xconsole_error)

    xc = GBA / "xconsole_client"
    if not xc.is_dir():
        _xconsole_error = (
            "grok-build-auth/xconsole_client 不存在。"
            "请确认仓库完整检出（该目录已内置，不再使用 git submodule）。"
        )
        raise RuntimeError(_xconsole_error)

    # Put vendored package root on sys.path so `import xconsole_client` works.
    gba_str = str(GBA.resolve())
    if gba_str not in sys.path:
        sys.path.insert(0, gba_str)

    try:
        # Import side-effect: validate package is loadable.
        import xconsole_client  # noqa: F401
        from xconsole_client import (  # noqa: F401
            XConsoleAuthClient,
            YesCaptchaSolver,
            create_solver,
            xai_oauth_login_protocol,
        )
        from xconsole_client.oauth_protocol import (  # noqa: F401
            extract_cookies_from_auth_client,
        )
        from xconsole_client.xai_oauth import (  # noqa: F401
            CLIPROXYAPI_GROK_HEADERS,
            build_cliproxyapi_auth_record,
        )
    except ModuleNotFoundError as e:
        missing = getattr(e, "name", None) or str(e)
        if missing in ("curl_cffi", "requests") or "curl_cffi" in str(e) or "requests" in str(e):
            _xconsole_error = (
                f"注册机依赖缺失: {missing}。请执行: pip install -r requirements.txt"
            )
        else:
            _xconsole_error = (
                f"无法导入 xconsole_client ({e})。请执行: pip install -r requirements.txt"
            )
        raise RuntimeError(_xconsole_error) from e
    except Exception as e:  # noqa: BLE001
        _xconsole_error = f"加载 grok-build-auth 失败: {e}"
        raise RuntimeError(_xconsole_error) from e

    _xconsole_ready = True
    _xconsole_error = None


def _local_solver_base_url(url: str | None = None) -> str:
    """Always pin local captcha to the in-container inline solver."""
    raw = (
        (url or "").strip()
        or (LOCAL_SOLVER_URL or "").strip()
        or os.environ.get("GROK2API_LOCAL_SOLVER_URL")
        or os.environ.get("LOCAL_SOLVER_URL")
        or "http://127.0.0.1:5072"
    ).strip().rstrip("/")
    # Registration must never hit an external "local" URL; force loopback.
    if (
        not raw
        or "127.0.0.1" not in raw
        and "localhost" not in raw
    ):
        return "http://127.0.0.1:5072"
    return raw


def probe_local_solver(
    url: str | None = None,
    *,
    timeout: float = 2.0,
) -> dict[str, Any]:
    """Probe inline Turnstile Solver readiness.

    HTTP up is enough to accept createTask (lazy browser mode warms on first
    solve). We prefer ``/health`` but also accept ``/`` returning any HTTP body.
    """
    base = _local_solver_base_url(url)
    out: dict[str, Any] = {
        "ok": False,
        "ready": False,
        "url": base,
        "http_up": False,
        "lazy": None,
        "pool_ready": None,
        "error": None,
        "status_code": None,
        "thread": None,
        "queue": None,
        "owned": None,
        "in_flight": None,
    }
    try:
        import urllib.error
        import urllib.request
    except Exception as e:  # noqa: BLE001
        out["error"] = f"urllib unavailable: {e}"
        return out

    # 1) /health — structured
    try:
        req = urllib.request.Request(
            f"{base}/health",
            headers={"Accept": "application/json"},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=max(0.5, float(timeout))) as resp:
            out["status_code"] = int(getattr(resp, "status", 200) or 200)
            body = resp.read().decode("utf-8", errors="replace")
        out["http_up"] = True
        try:
            data = json.loads(body) if body else {}
        except Exception:
            data = {}
        if isinstance(data, dict):
            out["lazy"] = data.get("lazy")
            out["pool_ready"] = data.get("pool_ready")
            for key in ("thread", "queue", "owned", "in_flight"):
                out[key] = data.get(key)
            # Solver process is ready when /health answers ok=true.
            # pool_ready may still be false under TURNSTILE_LAZY=1 — that is OK;
            # browsers warm on the first captcha task.
            if data.get("ok") is False:
                out["error"] = f"solver health ok=false body={body[:200]}"
            else:
                out["ok"] = True
                out["ready"] = True
                return out
        else:
            out["ok"] = True
            out["ready"] = True
            return out
    except Exception as e:  # noqa: BLE001
        out["error"] = f"health: {e}"

    # 2) fallback: any response from /
    try:
        req = urllib.request.Request(f"{base}/", method="GET")
        with urllib.request.urlopen(req, timeout=max(0.5, float(timeout))) as resp:
            out["status_code"] = int(getattr(resp, "status", 200) or 200)
            _ = resp.read(256)
        out["http_up"] = True
        out["ok"] = True
        out["ready"] = True
        out["error"] = None
        return out
    except Exception as e:  # noqa: BLE001
        if not out.get("error"):
            out["error"] = f"root: {e}"
        else:
            out["error"] = f"{out['error']}; root: {e}"
        return out


def wait_for_local_solver(
    url: str | None = None,
    *,
    timeout_sec: float | None = None,
    poll_sec: float | None = None,
    progress: Any | None = None,
) -> dict[str, Any]:
    """Block until local Turnstile Solver is HTTP-ready, or fail.

    Used by registration start so workers never race a still-booting solver.
    """
    base = _local_solver_base_url(url)
    try:
        wait_s = float(
            timeout_sec
            if timeout_sec is not None
            else LOCAL_SOLVER_WAIT_SEC
        )
    except (TypeError, ValueError):
        wait_s = 120.0
    wait_s = max(1.0, min(wait_s, 600.0))
    try:
        every = float(
            poll_sec if poll_sec is not None else LOCAL_SOLVER_POLL_SEC
        )
    except (TypeError, ValueError):
        every = 1.0
    every = max(0.2, min(every, 5.0))

    deadline = time.time() + wait_s
    last: dict[str, Any] = {
        "ok": False,
        "ready": False,
        "url": base,
        "waited_sec": 0.0,
        "error": "not started",
    }
    started = time.time()
    attempt = 0
    while True:
        attempt += 1
        last = probe_local_solver(base, timeout=min(2.0, every + 0.5))
        last["waited_sec"] = round(time.time() - started, 2)
        last["attempts"] = attempt
        last["url"] = base
        if last.get("ready"):
            last["ok"] = True
            if progress:
                try:
                    progress(
                        f"本地过盾已就绪 url={base} waited={last['waited_sec']}s"
                    )
                except Exception:
                    pass
            return last
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        msg = (
            f"等待本地过盾就绪… url={base} "
            f"attempt={attempt} left={remaining:.0f}s "
            f"err={last.get('error') or 'down'}"
        )
        if progress:
            try:
                progress(msg)
            except Exception:
                pass
        if attempt == 1 or attempt % 5 == 0:
            print(f"[grok-build-auth] {msg}")
        time.sleep(min(every, max(0.2, remaining)))

    last["ok"] = False
    last["ready"] = False
    last["error"] = (
        f"本地过盾服务未在 {wait_s:.0f}s 内就绪 "
        f"(url={base}; last={last.get('error') or 'unreachable'}). "
        f"请确认 inline Turnstile Solver 已启动（entrypoint / TURNSTILE_PORT），"
        f"或稍后重试注册。"
    )
    return last


def registration_available() -> dict[str, Any]:
    """Non-raising health probe for admin UI / startup logs."""
    moemail_configured = bool(
        os.environ.get("GROK2API_MOEMAIL_API_KEY")
        or os.environ.get("MOEMAIL_API_KEY")
    )
    try:
        from config import MOEMAIL_API_KEY as _cfg_moemail

        moemail_configured = moemail_configured or bool(_cfg_moemail)
    except Exception:
        pass
    provider = (
        CAPTCHA_PROVIDER
        or os.environ.get("GROK2API_CAPTCHA_PROVIDER")
        or os.environ.get("CAPTCHA_PROVIDER")
        or "local"
    ).strip().lower()
    if provider not in {"local", "yescaptcha"}:
        provider = "local"
    local_url = _local_solver_base_url(
        LOCAL_SOLVER_URL
        or os.environ.get("GROK2API_LOCAL_SOLVER_URL")
        or os.environ.get("LOCAL_SOLVER_URL")
        or ""
    )
    captcha_ready = bool(local_url) if provider == "local" else bool(YESCAPTCHA_KEY)
    local_solver_live: dict[str, Any] | None = None
    if provider == "local":
        local_solver_live = probe_local_solver(local_url, timeout=1.2)
        captcha_ready = bool(local_solver_live.get("ready"))
    try:
        ensure_xconsole()
        out = {
            "ok": True,
            "available": True,
            "engine": "dongguatanglinux/grok-build-auth",
            "path": str(GBA),
            "vendored": True,
            "adapter_build": ADAPTER_BUILD,
            "captcha_provider": provider,
            "local_solver_url": local_url,
            "local_solver_configured": bool(local_url),
            "local_solver_ready": (
                bool(local_solver_live.get("ready")) if local_solver_live else None
            ),
            "local_solver_probe": local_solver_live,
            "yescaptcha_configured": (
                captcha_ready if provider == "local" else bool(YESCAPTCHA_KEY)
            ),
            "moemail_configured": moemail_configured,
        }
        return out
    except Exception as e:  # noqa: BLE001
        return {
            "ok": False,
            "available": False,
            "engine": "dongguatanglinux/grok-build-auth",
            "path": str(GBA),
            "vendored": True,
            "adapter_build": ADAPTER_BUILD,
            "error": str(e),
            "captcha_provider": provider,
            "local_solver_url": local_url,
            "local_solver_configured": bool(local_url),
            "local_solver_ready": (
                bool(local_solver_live.get("ready")) if local_solver_live else None
            ),
            "local_solver_probe": local_solver_live,
            "yescaptcha_configured": (
                captcha_ready if provider == "local" else bool(YESCAPTCHA_KEY)
            ),
            "moemail_configured": moemail_configured,
        }


# --------------------------------------------------------------------------- #
# mail provider: moemail / yyds (reuse grokcli-2api config)
# --------------------------------------------------------------------------- #
def _make_email_receiver(
    *,
    api_key: str | None = None,
    base_url: str | None = None,
    prefix: str | None = None,
    domain: str | None = None,
    expiry_ms: int | None = None,
    mail_provider: str | None = None,
):
    from moemail import create_mailbox, fetch_messages, normalize_mail_provider
    from config import MOEMAIL_API_KEY, MOEMAIL_BASE_URL, MOEMAIL_DOMAIN, MOEMAIL_EXPIRY_MS

    key = (api_key or MOEMAIL_API_KEY or "").strip()
    if not key:
        raise ValueError(
            "Mail API key missing. Set GROK2API_MOEMAIL_API_KEY or pass api_key."
        )
    base = (base_url or MOEMAIL_BASE_URL).rstrip("/")
    prov = normalize_mail_provider(mail_provider, base_url=base)
    # YYDS/GPTMail/CFMail: empty domain means provider-side auto/random pick.
    # Never bleed MoeMail's MOEMAIL_DOMAIN (default example.com) into them.
    if prov in {"yyds", "gptmail", "cfmail"}:
        dom = (domain or "").strip().lstrip("@").strip(".")
    else:
        dom = (domain or MOEMAIL_DOMAIN or "").strip().lstrip("@").strip(".")
    # Generate a fresh local-part for every mailbox, including every job in a batch.
    # Ignore legacy fixed-prefix values such as "grok".
    alphabet = string.ascii_lowercase + string.digits
    pre = "".join(secrets.choice(alphabet) for _ in range(12))

    mailbox = create_mailbox(
        provider=prov,
        name=pre,
        domain=dom or None,
        expiry_ms=expiry_ms if expiry_ms is not None else MOEMAIL_EXPIRY_MS,
        api_key=key,
        base_url=base,
    )
    email_id = mailbox["id"]
    address = mailbox["email"]
    token = str(mailbox.get("token") or "")

    class _MailReceiver:
        def __init__(
            self,
            email: str,
            email_id: str,
            api_key: str | None,
            base_url: str | None,
            *,
            provider: str,
            token: str = "",
        ):
            self.email = email
            self.email_id = email_id
            self.api_key = api_key
            if provider == "yyds":
                default_base = "https://maliapi.215.im"
            elif provider == "gptmail":
                default_base = "https://mail.chatgpt.org.uk"
            elif provider == "cfmail":
                default_base = "https://temp-email-api.awsl.uk"
            else:
                default_base = "https://moemail.521884.xyz"
            self.base_url = base_url or default_base
            self.provider = provider
            self.token = token

        def wait_for_code(
            self,
            timeout: float = 120,
            *,
            should_cancel=None,
            poll_interval: float | None = None,
        ) -> str:
            import re as _re

            deadline = time.time() + float(timeout or 120)
            # Keep polls short so cooperative cancel can land quickly.
            poll = float(poll_interval if poll_interval is not None else 1.0)
            poll = max(0.4, min(poll, 2.0))
            while time.time() < deadline:
                if callable(should_cancel) and should_cancel():
                    raise _RegCancelled("cancelled while waiting for email code")
                try:
                    messages = fetch_messages(
                        self.email_id,
                        provider=self.provider,
                        api_key=self.api_key,
                        base_url=self.base_url,
                        include_details=True,
                        address=self.email,
                        token=self.token or None,
                    )
                    for item in messages:
                        # Prefer xAI AAA-BBB codes first.
                        text = "\n".join(
                            str(item.get(k) or "")
                            for k in (
                                "subject",
                                "content",
                                "text",
                                "textBody",
                                "html",
                                "htmlBody",
                                "body",
                                "from_address",
                                "from",
                                "verificationCode",
                            )
                        )
                        match = _re.search(
                            r"\b([A-Z0-9]{3})-([A-Z0-9]{3})\b", text, flags=_re.I
                        )
                        if match:
                            return "".join(match.groups()).upper()
                        # Also accept plain 6-char alnum codes from xAI mails.
                        match2 = _re.search(
                            r"\b([A-Z0-9]{6})\b", text, flags=_re.I
                        )
                        if match2 and "x.ai" in text.lower():
                            return match2.group(1).upper()
                        extracted = item.get("extracted") or {}
                        codes = extracted.get("codes") or []
                        for code in codes:
                            clean = str(code).replace("-", "").strip().upper()
                            if len(clean) == 6 and _re.fullmatch(r"[A-Z0-9]{6}", clean):
                                return clean
                except Exception:
                    pass
                # Sleep in small slices so stop can interrupt mid-wait.
                slept = 0.0
                while slept < poll:
                    if callable(should_cancel) and should_cancel():
                        raise _RegCancelled("cancelled while waiting for email code")
                    step = min(0.25, poll - slept)
                    time.sleep(step)
                    slept += step
                poll = min(2.0, poll + 0.15)
            raise RuntimeError("timeout waiting for xAI email verification code")

    return address, _MailReceiver(
        address,
        email_id,
        api_key=key,
        base_url=base,
        provider=prov,
        token=token,
    )


def _proxy_url() -> str:
    """Pick one proxy from the configured pool (env / registration config)."""
    try:
        from proxy_pool import resolve_proxy_for_request

        return resolve_proxy_for_request(fallback_env=True) or ""
    except Exception:
        try:
            from moemail import normalize_proxy_config
            from config import XAI_PROXY

            cfg = normalize_proxy_config(XAI_PROXY or None)
            return cfg["proxy"] if cfg else ""
        except Exception:
            return ""


def _proxy_pool(
    proxy_text: str | None = None,
    *,
    username: str | None = None,
    password: str | None = None,
) -> list[str]:
    """Parse multi-line proxy text into full proxy URLs."""
    try:
        from proxy_pool import parse_proxy_pool

        pool = parse_proxy_pool(
            proxy_text,
            username=username,
            password=password,
            fallback_env=True,
        )
        if pool:
            return pool
    except Exception:
        pass
    # Fallback: treat as single proxy via classic normalizer.
    one = (proxy_text or "").strip() or _proxy_url()
    return [one] if one else []


def _pick_proxy_from_pool(
    pool: list[str],
    *,
    strategy: str | None = None,
    index: int | None = None,
) -> str:
    try:
        from proxy_pool import pick_proxy, normalize_proxy_strategy

        strat = strategy
        if not strat:
            try:
                from config import XAI_PROXY_STRATEGY as _strat
            except Exception:
                _strat = "round_robin"
            strat = _strat
        return pick_proxy(pool, strategy=normalize_proxy_strategy(strat), index=index) or ""
    except Exception:
        return pool[0] if pool else ""


# --------------------------------------------------------------------------- #
# registration flow
# --------------------------------------------------------------------------- #
def _prepare_registration_session(
    *,
    yescaptcha_key: str,
    proxy: str,
    moemail_api_key: str | None = None,
    moemail_base_url: str | None = None,
    prefix: str | None = None,
    domain: str | None = None,
    expiry_ms: int | None = None,
    mail_provider: str | None = None,
    batch_id: str | None = None,
    batch_index: int | None = None,
    batch_total: int | None = None,
    start_delay: float = 0.0,
    post_registration: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create mailbox + session record. Does NOT start the registration worker."""
    if start_delay > 0:
        time.sleep(start_delay)

    try:
        email, receiver = _make_email_receiver(
            api_key=moemail_api_key,
            base_url=moemail_base_url,
            prefix=prefix,
            domain=domain,
            expiry_ms=expiry_ms,
            mail_provider=mail_provider,
        )
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}

    # xAI password rules: mix upper/lower/digit/symbol.
    password = f"Aa{os.urandom(5).hex()}9!xZ"
    sid = f"gba_{uuid.uuid4().hex[:16]}"

    created_at = _now()
    initial_message = f"queued; email={email}"
    sess = {
        "id": sid,
        "status": "queued",
        "created_at": created_at,
        "updated_at": created_at,
        "email": email,
        "password": password,
        "message": initial_message,
        "events": [{"at": created_at, "status": "queued", "message": initial_message}],
        "sso": None,
        "oauth": None,
        "auth_json": None,
        "error": None,
        "yescaptcha_key": yescaptcha_key,
        "proxy": proxy or None,
        "adapter_build": ADAPTER_BUILD,
        "batch_id": batch_id,
        "batch_index": batch_index,
        "batch_total": batch_total,
        # Keep receiver process-local only (not mirrored to Redis).
        "_receiver": receiver,
        "_post_registration": dict(post_registration or {}),
    }
    with _lock:
        _sessions[sid] = sess
        if batch_id and batch_id in _batches:
            _batches[batch_id]["session_ids"].append(sid)
            _batches[batch_id]["updated_at"] = _now()
            _mirror_reg_batch(batch_id, dict(_batches[batch_id]))
    _mirror_reg_sess(sid, sess)
    return {"ok": True, **_compact_session(sess)}


def _start_one_registration(
    *,
    yescaptcha_key: str,
    proxy: str,
    moemail_api_key: str | None = None,
    moemail_base_url: str | None = None,
    prefix: str | None = None,
    domain: str | None = None,
    expiry_ms: int | None = None,
    mail_provider: str | None = None,
    batch_id: str | None = None,
    batch_index: int | None = None,
    batch_total: int | None = None,
    start_delay: float = 0.0,
    post_registration: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create one session and spawn its worker thread (single-job path)."""
    prepared = _prepare_registration_session(
        yescaptcha_key=yescaptcha_key,
        proxy=proxy,
        moemail_api_key=moemail_api_key,
        moemail_base_url=moemail_base_url,
        prefix=prefix,
        domain=domain,
        expiry_ms=expiry_ms,
        mail_provider=mail_provider,
        batch_id=batch_id,
        batch_index=batch_index,
        batch_total=batch_total,
        start_delay=start_delay,
        post_registration=post_registration,
    )
    if not prepared.get("ok"):
        return prepared
    sid = str(prepared.get("id") or "")
    with _lock:
        sess = _sessions.get(sid) or {}
        receiver = sess.get("_receiver")
    if not sid or receiver is None:
        return {"ok": False, "error": "registration session prepare failed"}
    with _lock:
        if sid in _sessions:
            _sessions[sid]["status"] = "started"
            _sessions[sid]["message"] = f"started; email={_sessions[sid].get('email') or ''}"
            _sessions[sid]["updated_at"] = _now()
            _mirror_reg_sess(sid, _sessions[sid])
    # Single-job starts are not covered by the batch finalizer — log "running"
    # immediately so 任务日志 shows the registration task right away.
    if not batch_id:
        with _lock:
            started_sess = dict(_sessions.get(sid) or {})
        if started_sess:
            payload = _session_task_log_payload(started_sess)
            _record_register_task(
                task_id=payload["task_id"],
                summary=payload["summary"] or f"协议注册启动 {started_sess.get('email') or sid}",
                status="running",
                ok=None,
                progress_done=0,
                progress_total=1,
                finished=False,
                detail={**payload["detail"], "phase": "started"},
            )
    threading.Thread(
        target=_run_registration,
        args=(sid, yescaptcha_key, proxy or "", receiver),
        daemon=True,
        name=f"gba-reg-{sid[-8:]}",
    ).start()
    with _lock:
        sess = _sessions.get(sid)
        if sess is None:
            return prepared
        return {"ok": True, **_compact_session(sess)}


def start_registration(
    *,
    captcha_provider: str | None = None,
    local_solver_url: str | None = None,
    yescaptcha_key: str | None = None,
    proxy: str | None = None,
    proxy_username: str | None = None,
    proxy_password: str | None = None,
    proxy_strategy: str | None = None,
    moemail_api_key: str | None = None,
    moemail_base_url: str | None = None,
    prefix: str | None = None,
    domain: str | None = None,
    expiry_ms: int | None = None,
    mail_provider: str | None = None,
    count: int | None = None,
    concurrency: int | None = None,
    stagger_ms: int | None = None,
    probe_delay_sec: float | int | None = None,
    post_registration: dict[str, Any] | None = None,
    start_paused: bool = False,
    auto_tune_enabled: bool = False,
) -> dict[str, Any]:
    """Start one or many registration sessions (multi-thread).

    ``count`` > 1 enables batch mode. ``concurrency`` is the real in-flight
    limit: e.g. concurrency=3 means only 3 accounts register at the same time;
    when one finishes, the next queued account starts.

    ``proxy`` may be a single URL or a multi-line proxy pool. Each registration
    job picks one entry via ``proxy_strategy`` (round_robin / random / sticky).
    """
    try:
        ensure_xconsole()
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}

    _clean_old_sessions()

    # Allow admin form / env to override settle window for post-import probe.
    if probe_delay_sec is not None:
        try:
            globals()["REGISTER_PROBE_DELAY_SEC"] = max(
                0.0, min(600.0, float(probe_delay_sec))
            )
            os.environ["GROK2API_REG_PROBE_DELAY_SEC"] = str(
                int(globals()["REGISTER_PROBE_DELAY_SEC"])
            )
        except (TypeError, ValueError):
            pass

    provider = (
        captcha_provider
        or CAPTCHA_PROVIDER
        or os.environ.get("GROK2API_CAPTCHA_PROVIDER")
        or os.environ.get("CAPTCHA_PROVIDER")
        or "local"
    ).strip().lower()
    if provider not in {"local", "yescaptcha"}:
        provider = "local"
    try:
        globals()["CAPTCHA_PROVIDER"] = provider
    except Exception:
        pass

    if provider == "local":
        # Always inline in main container; ignore any external/custom URL.
        solver_url = _local_solver_base_url(local_solver_url)
        try:
            globals()["LOCAL_SOLVER_URL"] = solver_url
        except Exception:
            pass
        os.environ["GROK2API_LOCAL_SOLVER_URL"] = solver_url
        os.environ["LOCAL_SOLVER_URL"] = solver_url
        os.environ["GROK2API_YESCAPTCHA_ENDPOINT"] = solver_url
        os.environ["YESCAPTCHA_ENDPOINT"] = solver_url
        key = "local"
        # Gate: never spawn registration workers before the inline solver answers.
        # Lazy browser mode is fine (pool_ready may be false); HTTP /health is enough.
        solver_wait = wait_for_local_solver(solver_url)
        if not solver_wait.get("ready"):
            return {
                "ok": False,
                "error": solver_wait.get("error")
                or f"本地过盾未就绪: {solver_url}",
                "local_solver": solver_wait,
            }
    else:
        # Cloud YesCaptcha must not inherit local solver endpoint/key.
        try:
            globals()["LOCAL_SOLVER_URL"] = ""
        except Exception:
            pass
        for k in (
            "GROK2API_LOCAL_SOLVER_URL",
            "LOCAL_SOLVER_URL",
            "GROK2API_YESCAPTCHA_ENDPOINT",
            "YESCAPTCHA_ENDPOINT",
            "YESCAPTCHA_API_BASE",
        ):
            os.environ.pop(k, None)
        key = (
            yescaptcha_key
            or YESCAPTCHA_KEY
            or os.environ.get("GROK2API_YESCAPTCHA_KEY")
            or os.environ.get("YESCAPTCHA_API_KEY")
            or ""
        ).strip()
        if key == "local":
            key = ""
        if not key:
            return {
                "ok": False,
                "error": "YESCAPTCHA_KEY is required (set GROK2API_YESCAPTCHA_KEY, save in 协议注册配置, or pass yescaptcha_key)",
            }

    if key and key != YESCAPTCHA_KEY:
        # keep module attr in sync for subsequent workers
        try:
            globals()["YESCAPTCHA_KEY"] = key
        except Exception:
            pass

    try:
        n = int(count if count is not None else 1)
    except (TypeError, ValueError):
        n = 1
    n = max(1, n)

    try:
        workers = int(
            concurrency
            if concurrency is not None
            else DEFAULT_CONCURRENCY
        )
    except (TypeError, ValueError):
        workers = DEFAULT_CONCURRENCY
    requested_workers = max(1, min(workers, MAX_CONCURRENCY, n))
    performance_profile = get_registration_performance_profile(provider, local_solver_url)
    workers = requested_workers

    try:
        stagger = int(stagger_ms if stagger_ms is not None else 400)
    except (TypeError, ValueError):
        stagger = 400
    stagger = max(0, min(stagger, 60_000))

    # Build proxy pool once; each job picks one URL (rotation / random / sticky).
    proxy_pool = _proxy_pool(
        proxy,
        username=proxy_username,
        password=proxy_password,
    )
    try:
        from config import XAI_PROXY_STRATEGY as _default_strat
    except Exception:
        _default_strat = "round_robin"
    proxy_strat = (proxy_strategy or _default_strat or "round_robin").strip().lower()
    proxy_val = _pick_proxy_from_pool(proxy_pool, strategy=proxy_strat, index=0)
    try:
        from moemail import normalize_mail_provider as _norm_mail

        mail_prov = _norm_mail(mail_provider, base_url=moemail_base_url)
    except Exception:
        mail_prov = (mail_provider or "moemail").strip().lower() or "moemail"

    # Single job — keep original response shape for UI compatibility.
    if n == 1:
        return _start_one_registration(
            yescaptcha_key=key,
            proxy=proxy_val,
            moemail_api_key=moemail_api_key,
            moemail_base_url=moemail_base_url,
            prefix=prefix,
            domain=domain,
            expiry_ms=expiry_ms,
            mail_provider=mail_prov,
            post_registration=post_registration,
        )

    batch_id = f"batch_{uuid.uuid4().hex[:12]}"
    # Snapshot keeps the full multi-line text so resume / UI can re-parse the pool.
    proxy_snapshot = (proxy or "\n".join(proxy_pool) or proxy_val or "").strip()
    reg_cfg = _snapshot_reg_config(
        captcha_provider=provider,
        yescaptcha_key=key,
        proxy=proxy_snapshot,
        moemail_api_key=moemail_api_key,
        moemail_base_url=moemail_base_url,
        prefix=prefix,
        domain=domain,
        expiry_ms=expiry_ms,
        concurrency=workers,
        stagger_ms=stagger,
        mail_provider=mail_prov,
        post_registration=post_registration,
        auto_tune_enabled=auto_tune_enabled,
    )
    reg_cfg["proxy_strategy"] = proxy_strat
    reg_cfg["proxy_pool_count"] = len(proxy_pool)
    batch = {
        "id": batch_id,
        "status": "running",
        "created_at": _now(),
        "updated_at": _now(),
        "count": n,
        "concurrency": workers,
        "configured_concurrency": requested_workers,
        "stagger_ms": stagger,
        "scheduling_mode": "slot_fill",
        "auto_tune_enabled": bool(auto_tune_enabled),
        "performance_profile": performance_profile,
        "session_ids": [],
        "adapter_build": ADAPTER_BUILD,
        "message": f"batch started count={n} concurrency={workers}",
        "error": None,
        "finished": 0,
        "ok_count": 0,
        "fail_count": 0,
        "spawned": 0,
        "reg_config": reg_cfg,
        "owner_pid": os.getpid(),
        "runner_alive": True,
        "cancel_requested": False,
        "pause_requested": False,
    }
    with _lock:
        _batches[batch_id] = batch
    _mirror_reg_batch(batch_id, batch)
    # Log batch start so 任务日志 has a running row even before the first
    # session finishes (previously only the terminal row was written).
    _record_register_task(
        task_id=batch_id,
        summary=f"协议注册批次启动 count={n} concurrency={workers}",
        status="running",
        ok=None,
        progress_done=0,
        progress_total=n,
        finished=False,
        detail={
            "batch_id": batch_id,
            "count": n,
            "concurrency": workers,
            "stagger_ms": stagger,
            "phase": "started",
            "adapter_build": ADAPTER_BUILD,
        },
    )

    if start_paused:
        with _lock:
            paused_batch = _batches.get(batch_id) or batch
            paused_batch["status"] = "paused"
            paused_batch["pause_requested"] = True
            paused_batch["runner_alive"] = False
            paused_batch["message"] = f"paused 0/{n} (waiting for manual resume)"
            paused_batch["updated_at"] = _now()
            _batches[batch_id] = paused_batch
            _mirror_reg_batch(batch_id, dict(paused_batch))
        return {
            "ok": True,
            "batch": True,
            "batch_id": batch_id,
            "count": n,
            "concurrency": workers,
            "stagger_ms": stagger,
            "session_ids": [],
            "sessions": [],
            "status": "paused",
            "adapter_build": ADAPTER_BUILD,
            "message": f"paused batch created: count={n}, threads={workers}",
        }

    started = _spawn_batch_runner(
        batch_id,
        remaining=n,
        concurrency=workers,
        stagger_ms=stagger,
        captcha_provider=provider,
        yescaptcha_key=key,
        proxy=proxy_snapshot,
        proxy_strategy=proxy_strat,
        moemail_api_key=moemail_api_key,
        moemail_base_url=moemail_base_url,
        prefix=prefix,
        domain=domain,
        expiry_ms=expiry_ms,
        mail_provider=mail_prov,
        post_registration=post_registration,
        auto_tune_enabled=auto_tune_enabled,
    )
    if not started.get("ok"):
        return started

    # Brief wait so the first wave (up to `workers`) is usually visible to UI.
    time.sleep(min(0.45, 0.08 * workers + 0.08))
    with _lock:
        b = dict(_batches.get(batch_id) or batch)
        sids = list(b.get("session_ids") or [])
        sessions = [_compact_session(_sessions[s]) for s in sids if s in _sessions]

    return {
        "ok": True,
        "batch": True,
        "batch_id": batch_id,
        "count": n,
        "concurrency": workers,
        "configured_concurrency": requested_workers,
        "stagger_ms": stagger,
        "session_ids": sids,
        "sessions": sessions,
        "adapter_build": ADAPTER_BUILD,
        "message": (
            f"batch started: count={n}, threads={workers} "
            f"(in-flight cap), queued/started={len(sids)}"
        ),
        # Back-compat: first session fields for old UI single-session path.
        **(sessions[0] if sessions else {"id": None, "status": "starting"}),
    }


def _spawn_batch_runner(
    batch_id: str,
    *,
    remaining: int,
    concurrency: int,
    stagger_ms: int,
    captcha_provider: str,
    yescaptcha_key: str,
    proxy: str,
    proxy_strategy: str | None = None,
    moemail_api_key: str | None,
    moemail_base_url: str | None,
    prefix: str | None,
    domain: str | None,
    expiry_ms: int | None,
    mail_provider: str | None = None,
    post_registration: dict[str, Any] | None = None,
    auto_tune_enabled: bool = False,
) -> dict[str, Any]:
    """Start the ThreadPool spawner for a batch (also used by resume/reclaim)."""
    bid = str(batch_id or "").strip()
    if not bid:
        return {"ok": False, "error": "missing batch id"}
    batch = _load_reg_batch(bid)
    if not batch:
        return {"ok": False, "error": "registration batch not found"}

    if remaining <= 0:
        with _lock:
            b = _batches.get(bid) or dict(batch)
            b["runner_alive"] = False
            b["status"] = "done"
            b["updated_at"] = _now()
            b["message"] = "nothing to spawn"
            _batches[bid] = b
            _mirror_reg_batch(bid, dict(b))
        return {
            "ok": True,
            "batch_id": bid,
            "already_complete": True,
            "remaining": 0,
            "batch": get_registration_batch(bid),
        }

    acquired, lock_token = _try_acquire_batch_runner(bid)
    if not acquired:
        return {
            "ok": False,
            "error": "batch runner already active on another worker",
            "batch_id": bid,
            "already_running": True,
        }

    provider = (captcha_provider or "local").strip().lower()
    if provider not in {"local", "yescaptcha"}:
        provider = "local"
    key = (yescaptcha_key or "").strip()
    if provider == "local":
        key = "local"
        solver_url = _local_solver_base_url(None)
        try:
            globals()["CAPTCHA_PROVIDER"] = "local"
            globals()["LOCAL_SOLVER_URL"] = solver_url
        except Exception:
            pass
        os.environ["GROK2API_CAPTCHA_PROVIDER"] = "local"
        os.environ["CAPTCHA_PROVIDER"] = "local"
        os.environ["GROK2API_LOCAL_SOLVER_URL"] = solver_url
        os.environ["LOCAL_SOLVER_URL"] = solver_url
        os.environ["GROK2API_YESCAPTCHA_ENDPOINT"] = solver_url
        os.environ["YESCAPTCHA_ENDPOINT"] = solver_url
        solver_wait = wait_for_local_solver(solver_url)
        if not solver_wait.get("ready"):
            _release_batch_runner(bid, lock_token)
            return {
                "ok": False,
                "error": solver_wait.get("error")
                or f"本地过盾未就绪: {solver_url}",
                "batch_id": bid,
                "local_solver": solver_wait,
            }
    else:
        if not key:
            _release_batch_runner(bid, lock_token)
            return {
                "ok": False,
                "error": "YESCAPTCHA_KEY missing",
                "batch_id": bid,
            }
        try:
            globals()["CAPTCHA_PROVIDER"] = "yescaptcha"
            globals()["YESCAPTCHA_KEY"] = key
            globals()["LOCAL_SOLVER_URL"] = ""
        except Exception:
            pass
        for k in (
            "GROK2API_LOCAL_SOLVER_URL",
            "LOCAL_SOLVER_URL",
            "GROK2API_YESCAPTCHA_ENDPOINT",
            "YESCAPTCHA_ENDPOINT",
            "YESCAPTCHA_API_BASE",
        ):
            os.environ.pop(k, None)

    # `proxy` may be multi-line pool text; expand once for this runner.
    proxy_pool = _proxy_pool(proxy)
    try:
        from config import XAI_PROXY_STRATEGY as _default_strat
    except Exception:
        _default_strat = "round_robin"
    proxy_strat = (proxy_strategy or _default_strat or "round_robin").strip().lower()
    proxy_snapshot = (proxy or "\n".join(proxy_pool) or "").strip()
    workers = max(1, min(int(concurrency or DEFAULT_CONCURRENCY), MAX_CONCURRENCY, remaining))
    stagger = max(0, min(int(400 if stagger_ms is None else stagger_ms), 60_000))
    tuner = AdaptiveRegistrationTuner(bool(auto_tune_enabled), workers, stagger)
    pipeline_config = dict(post_registration or {})
    pipeline_config["pipeline_concurrency"] = workers

    with _lock:
        b = _batches.get(bid) or dict(batch)
        b["status"] = "running"
        b["cancel_requested"] = False
        b["pause_requested"] = False
        b["concurrency"] = workers
        b["stagger_ms"] = stagger
        b["scheduling_mode"] = "slot_fill"
        b["auto_tune_enabled"] = bool(auto_tune_enabled)
        b["auto_tune"] = tuner.snapshot(
            successes=int(b.get("ok_count") or 0),
            started_at=float(b.get("created_at") or _now()),
        )
        b["runner_alive"] = True
        b["owner_pid"] = os.getpid()
        b["adapter_build"] = ADAPTER_BUILD
        b["reg_config"] = _snapshot_reg_config(
            captcha_provider=provider,
            yescaptcha_key=key,
            proxy=proxy_snapshot,
            moemail_api_key=moemail_api_key,
            moemail_base_url=moemail_base_url,
            prefix=prefix,
            domain=domain,
            expiry_ms=expiry_ms,
            concurrency=workers,
            stagger_ms=stagger,
            mail_provider=mail_provider,
            post_registration=pipeline_config,
            auto_tune_enabled=auto_tune_enabled,
        )
        b["reg_config"]["proxy_strategy"] = proxy_strat
        b["reg_config"]["proxy_pool_count"] = len(proxy_pool)
        b["updated_at"] = _now()
        # Preserve historical counters when reclaiming after process restart;
        # only reset if this is a brand-new spawn with no prior progress.
        prior_finished = int(b.get("finished") or 0)
        prior_ok = int(b.get("ok_count") or 0)
        prior_fail = int(b.get("fail_count") or 0)
        b["message"] = (
            f"starting remaining={remaining} threads={workers}"
            + (f" already_done={prior_finished}" if prior_finished else "")
            + (f" proxies={len(proxy_pool)}" if proxy_pool else "")
        )
        if prior_finished <= 0 and not (b.get("session_ids") or []):
            b["finished"] = 0
            b["ok_count"] = 0
            b["fail_count"] = 0
        else:
            b["finished"] = prior_finished
            b["ok_count"] = prior_ok
            b["fail_count"] = prior_fail
        _batches[bid] = b
        _mirror_reg_batch(bid, dict(b))

    def _run_batch() -> None:
        from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

        errors: list[str] = []
        with _lock:
            _seed = dict(_batches.get(bid) or batch or {})
        finished = int(_seed.get("finished") or 0)
        ok_n = int(_seed.get("ok_count") or 0)
        fail_n = int(_seed.get("fail_count") or 0)
        stop_renew = False
        # Strict slot-fill scheduling: keep exactly the configured number of
        # jobs in flight and submit the next one as soon as any slot completes.
        next_i = 1
        in_flight: dict[Any, int] = {}

        def _max_inflight() -> int:
            if tuner.enabled:
                return max(1, int(tuner.current_concurrency))
            return max(1, workers)

        def _batch_cancel_requested() -> bool:
            with _lock:
                local = _batches.get(bid) or {}
            if local.get("cancel_requested") or str(local.get("status") or "").lower() in (
                "stopping",
                "cancelled",
                "stopped",
            ):
                return True
            if not _reg_redis():
                return False
            try:
                from store import sessions_redis

                remote = sessions_redis.reg_batch_get(bid)
                if not isinstance(remote, dict):
                    return False
                if remote.get("cancel_requested") or str(remote.get("status") or "").lower() in (
                    "stopping",
                    "cancelled",
                    "stopped",
                ):
                    with _lock:
                        cur = _batches.get(bid) or dict(remote)
                        cur["cancel_requested"] = True
                        if str(cur.get("status") or "").lower() not in (
                            "cancelled",
                            "stopped",
                            "done",
                            "partial",
                            "error",
                        ):
                            cur["status"] = remote.get("status") or "stopping"
                            if remote.get("message"):
                                cur["message"] = remote.get("message")
                        cur["updated_at"] = _now()
                        _batches[bid] = cur
                    return True
            except Exception:
                pass
            return False

        def _batch_pause_requested() -> bool:
            with _lock:
                local = _batches.get(bid) or {}
            if local.get("pause_requested") or str(local.get("status") or "").lower() in (
                "pausing",
                "paused",
            ):
                return True
            if not _reg_redis():
                return False
            try:
                from store import sessions_redis

                remote = sessions_redis.reg_batch_get(bid)
                if not isinstance(remote, dict):
                    return False
                if remote.get("pause_requested") or str(remote.get("status") or "").lower() in (
                    "pausing",
                    "paused",
                ):
                    with _lock:
                        cur = _batches.get(bid) or dict(remote)
                        cur["pause_requested"] = True
                        cur["status"] = "pausing"
                        cur["updated_at"] = _now()
                        _batches[bid] = cur
                    return True
            except Exception:
                pass
            return False

        def _renew_loop() -> None:
            while not stop_renew:
                time.sleep(max(5.0, REG_BATCH_RUNNER_LOCK_TTL / 3))
                if stop_renew:
                    break
                if _batch_cancel_requested():
                    # Keep heartbeat while draining, but mark status as stopping.
                    with _lock:
                        bb = _batches.get(bid)
                        if bb is not None:
                            bb["cancel_requested"] = True
                            if str(bb.get("status") or "").lower() not in (
                                "cancelled",
                                "stopped",
                                "done",
                                "partial",
                                "error",
                            ):
                                bb["status"] = "stopping"
                            bb["updated_at"] = _now()
                            bb["runner_alive"] = True
                            _mirror_reg_batch(bid, dict(bb))
                _renew_batch_runner(bid, lock_token)
                with _lock:
                    bb = _batches.get(bid)
                    if bb is not None:
                        bb["updated_at"] = _now()
                        bb["runner_alive"] = True
                        bb["owner_pid"] = os.getpid()
                        _mirror_reg_batch(bid, dict(bb))

        renew_t = threading.Thread(
            target=_renew_loop,
            daemon=True,
            name=f"gba-batch-lock-{bid[-8:]}",
        )
        renew_t.start()

        def _job(i: int) -> dict[str, Any]:
            # Honour batch-level stop before creating more mailboxes.
            if _batch_cancel_requested():
                return {
                    "ok": False,
                    "id": None,
                    "status": "cancelled",
                    "error": "cancelled before start",
                }
            # One proxy per registration job (pool rotation / random / sticky).
            job_proxy = _pick_proxy_from_pool(
                proxy_pool, strategy=proxy_strat, index=max(0, int(i) - 1)
            )
            # Small per-slot stagger only (not cumulative across the whole batch).
            active_slots = max(1, int(tuner.current_concurrency))
            delay = (tuner.stagger_ms / 1000.0) * ((i - 1) % active_slots)
            prepared = _prepare_registration_session(
                yescaptcha_key=key,
                proxy=job_proxy,
                moemail_api_key=moemail_api_key,
                moemail_base_url=moemail_base_url,
                prefix=prefix,
                domain=domain,
                expiry_ms=expiry_ms,
                mail_provider=mail_provider,
                batch_id=bid,
                batch_index=i,
                batch_total=int((_load_reg_batch(bid) or {}).get("count") or remaining),
                start_delay=delay,
                post_registration=pipeline_config,
            )
            if not prepared.get("ok"):
                return prepared
            sid = str(prepared.get("id") or "")
            with _lock:
                # Re-check cancel after prepare (user may stop mid-queue).
                b1 = _batches.get(bid) or {}
                sess = _sessions.get(sid) or {}
                if (
                    b1.get("cancel_requested")
                    or str(b1.get("status") or "").lower() in ("stopping", "cancelled", "stopped")
                    or sess.get("cancel_requested")
                ):
                    if sid in _sessions:
                        _sessions[sid]["status"] = "cancelled"
                        _sessions[sid]["message"] = "cancelled before worker start"
                        _sessions[sid]["error"] = "cancelled"
                        _sessions[sid]["cancel_requested"] = True
                        _sessions[sid]["updated_at"] = _now()
                        _sessions[sid].pop("_receiver", None)
                        _mirror_reg_sess(sid, _sessions[sid])
                    return {
                        "ok": False,
                        "id": sid,
                        "status": "cancelled",
                        "error": "cancelled",
                        "email": sess.get("email"),
                    }
                receiver = sess.get("_receiver")
                if sid in _sessions:
                    _sessions[sid]["status"] = "started"
                    _sessions[sid]["message"] = (
                        f"started; email={_sessions[sid].get('email') or ''}"
                    )
                    _sessions[sid]["updated_at"] = _now()
                    _mirror_reg_sess(sid, _sessions[sid])
            if not sid or receiver is None:
                return {"ok": False, "error": "registration session prepare failed", "id": sid}
            # Cross-batch admission control: many resumed batches otherwise all
            # run concurrency=8 and overwhelm local captcha + device-flow.
            admitted = False
            try:
                def _job_cancel() -> None:
                    with _lock:
                        sess2 = _sessions.get(sid) or {}
                        b2 = _batches.get(bid) or {}
                        if (
                            sess2.get("cancel_requested")
                            or b2.get("cancel_requested")
                        ):
                            raise _RegCancelled("cancelled while waiting for admission")

                _wait_reg_admission(check_cancel=_job_cancel)
                admitted = True
                _run_registration(sid, key, job_proxy or "", receiver)
            except _RegCancelled as e:
                with _lock:
                    if sid in _sessions:
                        _sessions[sid]["status"] = "cancelled"
                        _sessions[sid]["error"] = str(e)
                        _sessions[sid]["message"] = str(e)
                        _sessions[sid]["updated_at"] = _now()
                        _mirror_reg_sess(sid, _sessions[sid])
                return {
                    "ok": False,
                    "id": sid,
                    "status": "cancelled",
                    "error": str(e),
                }
            finally:
                if admitted:
                    _release_reg_admission()
                with _lock:
                    if sid in _sessions:
                        _sessions[sid].pop("_receiver", None)
            with _lock:
                final = _sessions.get(sid) or {}
            st = str(final.get("status") or "")
            ok = bool(final.get("imported_account_ids")) and st not in (
                "error",
                "failed",
                "cancelled",
                "stopped",
            )
            return {
                "ok": ok,
                "id": sid,
                "status": st,
                "error": final.get("error"),
                "email": final.get("email"),
            }

        def _note_result(idx: int, r: dict[str, Any] | None = None, exc: Exception | None = None) -> None:
            nonlocal finished, ok_n, fail_n
            finished += 1
            result_ok = bool(isinstance(r, dict) and r.get("ok") and exc is None)
            result_error = str(
                exc
                or ((r or {}).get("error") if isinstance(r, dict) else "")
                or ((r or {}).get("status") if isinstance(r, dict) else "")
                or ""
            )
            if exc is not None:
                fail_n += 1
                errors.append(f"#{idx}: {exc}")
            elif not isinstance(r, dict):
                fail_n += 1
                errors.append(f"#{idx}: empty result")
            elif r.get("ok"):
                ok_n += 1
            else:
                fail_n += 1
                errors.append(
                    f"#{idx}: {r.get('error') or r.get('status') or 'failed'}"
                )
            tuner.record(result_ok, result_error)
            if tuner.ready:
                solver_sample = (
                    probe_local_solver(None, timeout=0.75) if provider == "local" else {}
                )
                tuner.evaluate(system_sample(), solver_sample)
            with _lock:
                b = _batches.get(bid)
                if b is not None:
                    b["updated_at"] = _now()
                    # Don't clobber explicit stop marker.
                    if not b.get("cancel_requested") and not b.get("pause_requested"):
                        b["status"] = "running"
                    b["finished"] = finished
                    b["ok_count"] = ok_n
                    b["fail_count"] = fail_n
                    b["spawned"] = len(b.get("session_ids") or [])
                    b["spawn_errors"] = errors[-20:]
                    b["runner_alive"] = True
                    b["inflight"] = len(in_flight)
                    b["auto_tune"] = tuner.snapshot(
                        successes=ok_n,
                        started_at=float(b.get("created_at") or _now()),
                    )
                    b["message"] = (
                        f"running {finished}/{target_total} done "
                        f"(ok={ok_n} fail={fail_n}, threads={tuner.current_concurrency}, "
                        f"inflight={len(in_flight)})"
                    )
                    _mirror_reg_batch(bid, dict(b))

        try:
            target_total = int((_load_reg_batch(bid) or {}).get("count") or remaining)
            with ThreadPoolExecutor(
                max_workers=workers, thread_name_prefix=f"gba-batch-{bid[-6:]}"
            ) as pool:
                while True:
                    # Fill every free slot immediately; no wave/batch barrier.
                    while (
                        next_i <= remaining
                        and len(in_flight) < _max_inflight()
                        and not _batch_cancel_requested()
                        and not _batch_pause_requested()
                    ):
                        fut = pool.submit(_job, next_i)
                        in_flight[fut] = next_i
                        next_i += 1
                        with _lock:
                            bb = _batches.get(bid)
                            if bb is not None:
                                bb["inflight"] = len(in_flight)
                                bb["updated_at"] = _now()
                                if not bb.get("cancel_requested") and not bb.get("pause_requested"):
                                    bb["status"] = "running"
                                bb["message"] = (
                                    f"running {finished}/{target_total} done "
                                    f"(ok={ok_n} fail={fail_n}, threads={tuner.current_concurrency}, "
                                    f"inflight={len(in_flight)})"
                                )
                                _mirror_reg_batch(bid, dict(bb))

                    if not in_flight:
                        break

                    done, _pending = wait(
                        set(in_flight.keys()),
                        return_when=FIRST_COMPLETED,
                        timeout=0.5,
                    )
                    if not done:
                        # Timeout tick: re-check cancel and refresh progress.
                        if _batch_cancel_requested():
                            # Stop feeding new jobs; still drain in-flight workers.
                            pass
                        continue
                    for fut in done:
                        idx = in_flight.pop(fut, 0)
                        try:
                            r = fut.result()
                            _note_result(idx, r=r)
                        except Exception as e:  # noqa: BLE001
                            _note_result(idx, exc=e)

                    # If cancelled and no more work in flight, exit promptly.
                    if _batch_cancel_requested() and not in_flight:
                        break
                    if _batch_pause_requested() and not in_flight:
                        break
                    # If cancelled, do not submit more jobs even if capacity frees.
                    if _batch_cancel_requested():
                        continue
        finally:
            stop_renew = True
            # Best-effort cancel of any leftover futures (usually empty now).
            for fut in list(in_flight.keys()):
                try:
                    fut.cancel()
                except Exception:
                    pass
            with _lock:
                b = _batches.get(bid)
                if b is not None:
                    b["updated_at"] = _now()
                    b["finished"] = finished
                    b["ok_count"] = ok_n
                    b["fail_count"] = fail_n
                    b["spawned"] = len(b.get("session_ids") or [])
                    b["spawn_errors"] = errors[-20:]
                    b["runner_alive"] = False
                    b["inflight"] = 0
                    b["auto_tune"] = tuner.snapshot(
                        successes=ok_n,
                        started_at=float(b.get("created_at") or _now()),
                    )
                    target_total = int(b.get("count") or finished or 0)
                    cancelled = bool(b.get("cancel_requested")) or str(b.get("status") or "").lower() in (
                        "stopping",
                        "cancelled",
                        "stopped",
                    )
                    paused = bool(b.get("pause_requested")) or str(b.get("status") or "").lower() in (
                        "pausing",
                        "paused",
                    )
                    if paused and finished < target_total:
                        b["status"] = "paused"
                        b["message"] = (
                            f"paused {finished}/{target_total} "
                            f"(ok={ok_n} fail={fail_n}, threads={tuner.current_concurrency})"
                        )
                    elif cancelled and finished < target_total:
                        b["status"] = "cancelled"
                        b["message"] = (
                            f"stopped {finished}/{target_total} "
                            f"(ok={ok_n} fail={fail_n}, threads={tuner.current_concurrency})"
                        )
                    elif fail_n and not ok_n:
                        b["status"] = "error"
                        b["error"] = "; ".join(errors[:5]) or "all failed"
                        b["message"] = (
                            f"finished {finished}/{target_total} "
                            f"(ok={ok_n} fail={fail_n}, threads={tuner.current_concurrency})"
                            + (f"; errors={len(errors)}" if errors else "")
                        )
                    elif fail_n:
                        b["status"] = "partial"
                        b["message"] = (
                            f"finished {finished}/{target_total} "
                            f"(ok={ok_n} fail={fail_n}, threads={tuner.current_concurrency})"
                            + (f"; errors={len(errors)}" if errors else "")
                        )
                    else:
                        b["status"] = "done"
                        b["message"] = (
                            f"finished {finished}/{target_total} "
                            f"(ok={ok_n} fail={fail_n}, threads={tuner.current_concurrency})"
                        )
                    _mirror_reg_batch(bid, dict(b))
                    st = str(b.get("status") or "done")
                    _record_register_task(
                        task_id=str(bid),
                        summary=str(b.get("message") or f"协议注册批次 {bid}"),
                        status=st,
                        ok=st in {"done", "partial"} and ok_n > 0,
                        progress_done=int(finished or 0),
                        progress_total=int(target_total or finished or 0),
                        finished=True,
                        detail={
                            "batch_id": bid,
                            "ok_count": ok_n,
                            "fail_count": fail_n,
                            "threads": tuner.current_concurrency,
                            "status": st,
                            "errors": (errors or [])[:10],
                            "phase": "finished",
                            "adapter_build": ADAPTER_BUILD,
                        },
                    )
            _close_pipeline_phase(bid, "probe")
            _close_pipeline_phase(bid, "import")
            _release_batch_runner(bid, lock_token)

    threading.Thread(
        target=_run_batch,
        daemon=True,
        name=f"gba-batch-{bid[-8:]}",
    ).start()

    return {
        "ok": True,
        "batch_id": bid,
        "remaining": remaining,
        "concurrency": workers,
        "auto_tune": tuner.snapshot(
            successes=int(batch.get("ok_count") or 0),
            started_at=float(batch.get("created_at") or _now()),
        ),
        "message": f"started batch {bid}: remaining={remaining} threads={workers}",
    }


def _run_registration(
    sid: str,
    yescaptcha_key: str,
    proxy: str,
    receiver: Any,
) -> None:
    with _lock:
        sess = _sessions.get(sid)
    if not sess:
        # Another worker may hold the durable copy; still try to load.
        sess = _load_reg_sess(sid)
    if not sess:
        return
    # Re-bind process-local map so later progress stays readable on this worker.
    with _lock:
        _sessions[sid] = sess

    def _refresh_cancel_from_redis() -> None:
        """Pull cancel_requested from Redis so multi-worker stop works.

        Also honour batch-level stop so stopping a batch reaches in-flight
        sessions even if the session mirror lags.
        """
        if not _reg_redis():
            return
        try:
            from store import sessions_redis

            remote = sessions_redis.reg_sess_get(sid)
            batch_cancel = False
            remote_batch = None
            bid = ""
            with _lock:
                local_sess = _sessions.get(sid) or sess or {}
                bid = str(local_sess.get("batch_id") or "")
            if not bid and isinstance(remote, dict):
                bid = str(remote.get("batch_id") or "")
            if bid:
                try:
                    remote_batch = sessions_redis.reg_batch_get(bid)
                except Exception:
                    remote_batch = None
                if isinstance(remote_batch, dict) and (
                    remote_batch.get("cancel_requested")
                    or _is_cancel_status(remote_batch.get("status"))
                ):
                    batch_cancel = True
                    with _lock:
                        bb = _batches.get(bid) or dict(remote_batch)
                        bb["cancel_requested"] = True
                        if str(bb.get("status") or "").lower() not in (
                            "cancelled",
                            "stopped",
                            "done",
                            "partial",
                            "error",
                        ):
                            bb["status"] = remote_batch.get("status") or "stopping"
                        bb["updated_at"] = _now()
                        _batches[bid] = bb

            sess_cancel = isinstance(remote, dict) and (
                remote.get("cancel_requested")
                or _is_cancel_status(remote.get("status"))
            )
            if not sess_cancel and not batch_cancel:
                return
            with _lock:
                cur = _sessions.get(sid) or sess
                cur["cancel_requested"] = True
                if str(cur.get("status") or "").lower() not in _TERMINAL_STATUSES:
                    if sess_cancel and str(remote.get("status") or "").lower() in (
                        "stopping",
                        "cancelled",
                        "stopped",
                    ):
                        cur["status"] = remote.get("status") or "stopping"
                        if remote.get("message"):
                            cur["message"] = remote.get("message")
                    elif batch_cancel:
                        cur["status"] = "stopping"
                        cur["message"] = "stop requested via batch"
                _sessions[sid] = cur
        except Exception:
            pass

    def update(status: str, message: str, **kwargs: Any) -> None:
        _refresh_cancel_from_redis()
        with _lock:
            cur = _sessions.get(sid) or sess
            # Batch-level cancel also aborts this worker.
            bid = str(cur.get("batch_id") or "")
            batch_hit = False
            if bid:
                bb = _batches.get(bid) or {}
                if bb.get("cancel_requested") or _is_cancel_status(bb.get("status")):
                    batch_hit = True
                    cur["cancel_requested"] = True
            # Do not overwrite a terminal cancel with intermediate progress.
            if (_session_cancel_requested(cur) or batch_hit) and status not in (
                "cancelled",
                "stopped",
                "error",
                "imported",
            ):
                raise _RegCancelled(cur.get("message") or "cancelled by user")
            now = _now()
            previous_status = str(cur.get("_phase_status") or "")
            previous_started = float(cur.get("_phase_started_at") or 0.0)
            if previous_status and previous_status != status and previous_started > 0:
                stage = _REGISTRATION_STAGE_BY_STATUS.get(previous_status)
                if stage:
                    durations = dict(cur.get("phase_durations") or {})
                    durations[stage] = round(
                        float(durations.get(stage) or 0.0) + max(0.0, now - previous_started),
                        3,
                    )
                    cur["phase_durations"] = durations
            if status in _REGISTRATION_STAGE_BY_STATUS:
                if previous_status != status:
                    cur["_phase_status"] = status
                    cur["_phase_started_at"] = now
            else:
                cur.pop("_phase_status", None)
                cur.pop("_phase_started_at", None)
            cur["status"] = status
            cur["message"] = message
            cur["updated_at"] = now
            cur.update(kwargs)
            _append_session_event(cur, status, message, at=now)
            _sessions[sid] = cur
            _mirror_reg_sess(sid, cur)

    def _check_cancel() -> None:
        _refresh_cancel_from_redis()
        with _lock:
            cur = _sessions.get(sid) or sess
            bid = str(cur.get("batch_id") or "")
            if bid:
                bb = _batches.get(bid) or {}
                if bb.get("cancel_requested") or _is_cancel_status(bb.get("status")):
                    cur["cancel_requested"] = True
                    _sessions[sid] = cur
        if _session_cancel_requested(cur):
            raise _RegCancelled(cur.get("message") or "cancelled by user")

    email = str(sess.get("email") or "").strip().lower()
    password = sess.get("password") or ""
    if not password:
        update("error", "missing password for registration session", error="missing password")
        return
    sess["email"] = email
    client = None

    try:
        _check_cancel()
        ensure_xconsole()
        from xconsole_client import (
            XConsoleAuthClient,
            YesCaptchaSolver,
            xai_oauth_login_protocol,
        )
        from xconsole_client import config as C
        from xconsole_client.oauth_protocol import extract_cookies_from_auth_client
        from xconsole_client.xai_oauth import (
            CLIPROXYAPI_GROK_HEADERS,
            build_cliproxyapi_auth_record,
        )
        import accounts
        from config import UPSTREAM_BASE

        update("registering", "visiting signup page")
        _check_cancel()
        client = XConsoleAuthClient(
            debug=True,
            proxy=proxy or "",
            signup_url="https://accounts.x.ai/sign-up?redirect=grok-com",
        )
        client.visit_home()
        _check_cancel()
        client.load_signup_page()

        sitekey = (
            getattr(client, "turnstile_sitekey", None)
            or getattr(C, "TURNSTILE_SITEKEY", None)
            or ""
        ).strip()
        website_url = (getattr(client, "signup_url", None) or C.SIGNUP_URL or "").strip()
        if not sitekey:
            raise RuntimeError(
                "Turnstile sitekey missing. Signup page scrape failed and "
                "config TURNSTILE_SITEKEY is empty."
            )

        provider = (
            CAPTCHA_PROVIDER
            or os.environ.get("GROK2API_CAPTCHA_PROVIDER")
            or os.environ.get("CAPTCHA_PROVIDER")
            or "local"
        ).strip().lower()
        if provider not in {"local", "yescaptcha"}:
            provider = "local"

        if provider == "local":
            # Always use in-container inline solver; ignore external/custom URL.
            endpoint = _local_solver_base_url(None)
            solver_key = "local"
            auto_fallback = False
            # Re-check right before first solve so a mid-batch solver restart
            # doesn't burn mailboxes while HTTP is still down.
            wait = wait_for_local_solver(
                endpoint,
                timeout_sec=min(60.0, max(5.0, LOCAL_SOLVER_WAIT_SEC)),
                progress=lambda m: update("waiting_solver", m),
            )
            if not wait.get("ready"):
                raise RuntimeError(
                    wait.get("error")
                    or f"本地过盾未就绪，无法开始打码: {endpoint}"
                )
        else:
            # Cloud YesCaptcha only; never inherit local solver endpoint.
            endpoint = (
                os.environ.get("GROK2API_YESCAPTCHA_ENDPOINT")
                or os.environ.get("YESCAPTCHA_ENDPOINT")
                or os.environ.get("YESCAPTCHA_API_BASE")
                or ""
            ).strip() or None
            # Guard against accidental local leftover endpoint.
            if endpoint and (
                "127.0.0.1" in endpoint
                or "localhost" in endpoint
                or endpoint.rstrip("/").endswith(":5072")
            ):
                endpoint = None
            solver_key = (
                yescaptcha_key
                or YESCAPTCHA_KEY
                or os.environ.get("GROK2API_YESCAPTCHA_KEY")
                or os.environ.get("YESCAPTCHA_API_KEY")
                or ""
            ).strip()
            if not solver_key or solver_key == "local":
                raise RuntimeError("YesCaptcha 模式需要有效的 YESCAPTCHA_KEY")
            auto_fallback = True

        def _turnstile_progress(msg: str) -> None:
            # Raise cancel out of solver polling so stop doesn't wait full captcha timeout.
            _check_cancel()
            update("solving_turnstile", f"Turnstile: {msg}")

        solver = YesCaptchaSolver(
            solver_key,
            endpoint=endpoint,
            # Keep captcha wait bounded; cancel still interrupts via on_progress.
            timeout=float(os.environ.get("GROK2API_YESCAPTCHA_TIMEOUT", "120") or 120),
            poll_interval=float(os.environ.get("GROK2API_YESCAPTCHA_POLL", "2") or 2),
            debug=True,
            on_progress=_turnstile_progress,
            # Local: no cloud fallback. YesCaptcha: allow cn/global peer fallback.
            auto_fallback_endpoint=auto_fallback,
        )
        print(
            f"[grok-build-auth] turnstile provider={provider} website_url={website_url} "
            f"sitekey={sitekey} endpoint={getattr(solver, '_endpoint', '?')}"
        )

        # Critical ordering:
        # 1) solve Turnstile first (slow, ~20-40s)
        # 2) send email code
        # 3) wait for mailbox code
        # 4) immediately verify + create_account
        # Old order verified the code then waited for captcha; create_account then
        # failed with WKE=email:invalid-validation-code because the code expired /
        # was single-use after the slow captcha step.
        solver_label = "本地过盾" if provider == "local" else "YesCaptcha"
        update("solving_turnstile", f"solving Turnstile via {solver_label} (before email code)")
        _check_cancel()

        def _solve_turnstile(url: str, *, premium: bool = True) -> Any:
            # Bound local solves to the configured Camoufox browser slots while
            # keeping YesCaptcha requests independently parallel.
            # Local Camoufox has no premium tier — force Proxyless only.
            use_premium = bool(premium) and provider != "local"
            kwargs = {
                "website_url": url,
                "website_key": sitekey,
                "premium": use_premium,
                "fallback_non_premium": True,
            }
            if provider == "local":
                with _local_captcha_slots:
                    _check_cancel()
                    try:
                        return solver.solve_turnstile(**kwargs)
                    except Exception as e:
                        # Camoufox queue meltdown / timeout → brief global pause
                        msg = str(e).lower()
                        if any(
                            k in msg
                            for k in (
                                "timeout",
                                "timed out",
                                "queue",
                                "busy",
                                "no browser",
                                "target closed",
                                "crashed",
                            )
                        ):
                            _note_reg_pressure(f"local captcha: {e}")
                        raise
            return solver.solve_turnstile(**kwargs)

        try:
            # Local: Proxyless only. Remote YesCaptcha: premium M1 first.
            turnstile = _solve_turnstile(website_url, premium=(provider != "local"))
        except _RegCancelled:
            raise
        except Exception as captcha_err:
            _check_cancel()
            alt_url = "https://accounts.x.ai/sign-up?redirect=cloud-console"
            if website_url.rstrip("/") == alt_url.rstrip("/"):
                alt_url = "https://accounts.x.ai/sign-up?redirect=grok-com"
            update(
                "solving_turnstile",
                f"primary Turnstile failed ({captcha_err}); retry {alt_url}",
            )
            turnstile = _solve_turnstile(alt_url, premium=False)
        if not turnstile:
            raise RuntimeError("YesCaptcha returned empty Turnstile token")
        _check_cancel()

        # Password can be validated any time before create; do it while warm.
        client.validate_password(email, password)

        update("registering", "sending email validation code")
        _check_cancel()
        send_res = client.create_email_validation_code(email)
        if hasattr(send_res, "ok") and send_res.ok is False:
            print(
                f"[grok-build-auth] CreateEmailValidationCode ok=False "
                f"http={getattr(send_res, 'http_status', None)} "
                f"grpc={getattr(send_res, 'grpc_status', None)}"
            )

        update("waiting_email", "waiting for xAI verification code")
        # Poll mailbox with cancel-aware receiver so stop lands in ~0.25–1s.
        _check_cancel()

        def _mail_should_cancel() -> bool:
            # _check_cancel raises _RegCancelled when stop is requested.
            _check_cancel()
            return False

        try:
            code = receiver.wait_for_code(
                timeout=120.0,
                should_cancel=_mail_should_cancel,
                poll_interval=1.0,
            )
        except TypeError:
            # Older receiver signature fallback.
            code = None
            mail_deadline = time.time() + 120.0
            while time.time() < mail_deadline:
                _check_cancel()
                try:
                    code = receiver.wait_for_code(
                        timeout=min(4.0, max(1.0, mail_deadline - time.time()))
                    )
                except Exception:
                    code = None
                if code:
                    break
        if not code:
            raise RuntimeError("email verification code timeout")
        code = str(code or "").strip().upper().replace(" ", "").replace("-", "")
        if len(code) != 6:
            raise RuntimeError(
                f"invalid email verification code shape: {code!r} "
                f"(expect 6 alnum chars)"
            )
        update("registering", f"code received: {code}; verifying + creating immediately")

        # Prefer empty castle token (YesCaptcha cannot mint Castle fingerprints).
        # Retry create_account once with a fresh Turnstile + fresh email code when
        # the first flight is a structured hard error (expired code / turnstile).
        create_attempts = 2
        res = None
        sc: list[str] = []
        rsc_body = ""
        rsc_preview = ""
        http_status = 0
        signup_err: str | None = None
        for ca in range(1, create_attempts + 1):
            if ca > 1:
                # Full refresh path for invalid code / captcha failures.
                update(
                    "solving_turnstile",
                    f"create_account hard error ({signup_err}); refreshing Turnstile+email code",
                )
                try:
                    turnstile = _solve_turnstile(
                        website_url, premium=(provider != "local")
                    )
                except Exception as captcha_err:  # noqa: BLE001
                    print(f"[grok-build-auth] turnstile refresh failed: {captcha_err}")
                    break
                # New email code required after invalid-validation-code.
                try:
                    client.create_email_validation_code(email)
                    update("waiting_email", "waiting for fresh xAI verification code")
                    code = receiver.wait_for_code(timeout=120)
                    code = (
                        str(code or "")
                        .strip()
                        .upper()
                        .replace(" ", "")
                        .replace("-", "")
                    )
                    if len(code) != 6:
                        raise RuntimeError(f"fresh email code invalid: {code!r}")
                    update("registering", f"fresh code received: {code}")
                except Exception as mail_err:  # noqa: BLE001
                    print(f"[grok-build-auth] email code refresh failed: {mail_err}")
                    break

            # verify immediately before create_account (same second when possible)
            try:
                vres = client.verify_email_validation_code(email, code)
                print(
                    f"[grok-build-auth] VerifyEmailValidationCode "
                    f"ok={getattr(vres, 'ok', None)} "
                    f"http={getattr(vres, 'http_status', None)} "
                    f"grpc={getattr(vres, 'grpc_status', None)}"
                )
            except Exception as v_err:  # noqa: BLE001
                print(f"[grok-build-auth] verify_email error: {v_err}")

            update(
                "creating_account",
                f"creating xAI account (attempt {ca}/{create_attempts})",
            )
            res = client.create_account(
                email=email,
                given_name="User",
                family_name="Grok",
                password=password,
                email_validation_code=code,
                turnstile_token=turnstile,
                castle_request_token="",
                conversion_id=str(uuid.uuid4()),
            )
            sc = list(getattr(res, "set_cookies", None) or [])
            rsc_body = getattr(res, "rsc_body", "") or ""
            rsc_preview = rsc_body[:800]
            http_status = int(getattr(res, "http_status", 0) or 0)
            try:
                signup_err = client.extract_signup_error(rsc_body)
            except Exception:
                signup_err = None
            print(f"[grok-build-auth] create_account HTTP={http_status}")
            print(f"[grok-build-auth] create_account set-cookies count={len(sc)}")
            print(f"[grok-build-auth] create_account ok={bool(getattr(res, 'ok', False))}")
            print(f"[grok-build-auth] create_account error={signup_err!r}")
            print(f"[grok-build-auth] create_account rsc_body preview: {rsc_preview}")
            print(f"[grok-build-auth] adapter_build={ADAPTER_BUILD}")
            sess["create_account_http"] = http_status
            sess["create_account_ok_flag"] = bool(getattr(res, "ok", False))
            sess["create_account_set_cookies"] = len(sc)
            sess["create_account_error"] = signup_err

            # Persist full body for offline diagnosis (truncated).
            try:
                debug_path = (
                    RUNTIME_DATA_DIR / "register_sso" / f"{sid}.create_account.rsc.txt"
                )
                debug_path.parent.mkdir(parents=True, exist_ok=True)
                debug_path.write_text(rsc_body[:200_000], encoding="utf-8")
            except Exception:
                pass

            if http_status != 200:
                # Non-200 is terminal for this attempt; try once more only on 5xx.
                if http_status >= 500 and ca < create_attempts:
                    continue
                raise RuntimeError(
                    "create_account transport failed. "
                    f"adapter_build={ADAPTER_BUILD}; HTTP {http_status}; "
                    f"error={signup_err!r}; set_cookies={len(sc)}; "
                    f"body_preview={rsc_preview!r}"
                )

            # Structured hard error: retry with fresh captcha when recoverable.
            if signup_err:
                recoverable = any(
                    x in str(signup_err).lower()
                    for x in (
                        "turnstile",
                        "rate_limited",
                        "rate limit",
                        "captcha",
                        "account_signup_error",
                    )
                )
                if recoverable and ca < create_attempts:
                    continue
                raise RuntimeError(
                    "create_account rejected by xAI. "
                    f"adapter_build={ADAPTER_BUILD}; HTTP {http_status}; "
                    f"error={signup_err!r}; set_cookies={len(sc)}; "
                    f"body_preview={rsc_preview!r}"
                )

            # HTTP 200 without structured error — proceed even if res.ok is False
            # due to historical false negatives on RSC-only flights.
            break

        update(
            "fetching_sso",
            f"create_account HTTP {http_status} accepted; extracting SSO [{ADAPTER_BUILD}]",
        )

        sso = None
        try:
            sso = client.fetch_sso_token(
                email=email,
                password=password,
                save=True,
                output_dir=str(RUNTIME_DATA_DIR / "sso_output"),
                retries=4,
            )
        except Exception as sso_fetch_err:  # noqa: BLE001
            print(f"[grok-build-auth] fetch_sso_token error: {sso_fetch_err}")

        if not sso:
            try:
                from xconsole_client.sso import (
                    SSOExtractor,
                    parse_all_set_cookie_urls,
                    parse_sso_from_set_cookies,
                    parse_sso_jwt_url,
                    parse_sso_token_from_text,
                )

                sso = parse_sso_from_set_cookies(sc) or parse_sso_token_from_text(
                    rsc_body
                )
                if not sso and rsc_body:
                    print(
                        f"[grok-build-auth] set-cookie candidates="
                        f"{parse_all_set_cookie_urls(rsc_body)[:3]}"
                    )
                    print(
                        f"[grok-build-auth] primary set-cookie url="
                        f"{parse_sso_jwt_url(rsc_body)}"
                    )
                    extractor = SSOExtractor(
                        transport_request=client._request,
                        base_headers=client._base_headers,
                        cookie_jar=client._t.cookies,
                        debug=True,
                    )
                    sso = extractor.extract(
                        rsc_body, email=email, password=password, save=False
                    )
            except Exception as recover_err:  # noqa: BLE001
                print(f"[grok-build-auth] SSO recover failed: {recover_err}")

        # Current xAI create_account often returns only RSC chunks + CF cookies,
        # with no set-cookie JWT chain. Fall back to password CreateSession and
        # treat the returned session JWT as the sso cookie for sso_to_auth_json.
        if not sso:
            update(
                "fetching_sso",
                f"RSC has no sso chain; CreateSession password fallback [{ADAPTER_BUILD}]",
            )
            try:
                # Fresh turnstile for sign-in page improves CreateSession success.
                # Allow account propagation delay before first login attempt.
                time.sleep(2.0)
                signin_url = "https://accounts.x.ai/sign-in?redirect=grok-com"
                try:
                    signin_turnstile = _solve_turnstile(
                        signin_url, premium=(provider != "local")
                    )
                except Exception:
                    signin_turnstile = turnstile
                sso = client.obtain_session_via_password(
                    email=email,
                    password=password,
                    turnstile_token=signin_turnstile,
                    referer=signin_url,
                    retries=4,
                )
                # One more captcha + login if first CreateSession returned empty.
                if not sso:
                    try:
                        signin_turnstile = _solve_turnstile(signin_url, premium=False)
                        time.sleep(1.5)
                        sso = client.obtain_session_via_password(
                            email=email,
                            password=password,
                            turnstile_token=signin_turnstile,
                            referer=signin_url,
                            retries=2,
                        )
                    except Exception as cs2_err:  # noqa: BLE001
                        print(
                            f"[grok-build-auth] CreateSession second pass failed: {cs2_err}"
                        )
                print(
                    f"[grok-build-auth] CreateSession fallback sso="
                    f"{(sso[:60] if sso else None)}"
                )
            except Exception as cs_err:  # noqa: BLE001
                print(f"[grok-build-auth] CreateSession fallback failed: {cs_err}")

        print(f"[grok-build-auth] fetch_sso_token result: {sso[:60] if sso else None}")
        sess["sso"] = sso
        session_cookies = extract_cookies_from_auth_client(client)
        print(
            f"[grok-build-auth] session cookies after signup: "
            f"{sorted((session_cookies or {}).keys())}"
        )
        if sso:
            session_cookies = dict(session_cookies or {})
            session_cookies["sso"] = sso
            session_cookies["sso-rw"] = sso

        if not sso:
            raise RuntimeError(
                "SSO_COOKIE_MISSING after create_account. "
                f"adapter_build={ADAPTER_BUILD}; HTTP {http_status}; "
                f"create_ok={bool(getattr(res, 'ok', False))}; "
                f"signup_error={signup_err!r}; set_cookies={len(sc)}; "
                f"cookie_keys={sorted((session_cookies or {}).keys())}; "
                f"body_preview={rsc_preview!r}. "
                "Account may have been created, but neither RSC set-cookie chain "
                "nor CreateSession password fallback produced an sso cookie. "
                "Common causes: turnstile_failed, rate_limited, or account not yet "
                "visible to CreateSession."
            )

        # Required path: SSO/session JWT -> sso_to_auth_json device flow -> auth.json
        update(
            "importing",
            f"SSO obtained; converting via sso_to_auth_json [{ADAPTER_BUILD}]",
        )
        import sso_to_auth_json as sso_import

        token = sso_import.sso_to_token(sso)
        if not token or not token.get("access_token"):
            _note_reg_pressure("device-flow conversion failed", pause_sec=10)
            raise RuntimeError(
                "SSO obtained but sso_to_auth_json conversion failed "
                "(device verify/approve/token poll; often xAI device-flow "
                "rate_limited/slow_down under concurrent registration). "
                f"adapter_build={ADAPTER_BUILD}; sso_prefix={sso[:24]!r}"
            )
        _key, entry = sso_import.token_to_auth_entry(token, email=email)
        auth_payload = {
                "key": entry["key"],
                "access_token": token.get("access_token", ""),
                "auth_mode": entry.get("auth_mode", "oidc"),
                "email": entry.get("email") or email,
                "refresh_token": entry.get("refresh_token", ""),
                "id_token": token.get("id_token", ""),
                "token_type": token.get("token_type", "Bearer"),
                "expires_in": token.get("expires_in"),
                "expires_at": entry.get("expires_at"),
                "scope": token.get("scope", ""),
                "oidc_issuer": entry.get("oidc_issuer", "https://auth.x.ai"),
                "oidc_client_id": entry.get("oidc_client_id", ""),
                "sso": sso,
                "password": password,
            }
        pipeline_cfg = dict(sess.get("_post_registration") or {})
        output_target = str(
            pipeline_cfg.get("output_format") or pipeline_cfg.get("target") or "cpa"
        ).strip().lower()
        output_format = "sub2api" if output_target == "sub2api" else "cpa"
        import_result = accounts.import_auth_payload(
            auth_payload,
            merge=True,
            output_format=output_format,
        )
        if not import_result.get("ok"):
            raise RuntimeError(
                f"SSO account import failed: {import_result.get('error')}; "
                f"adapter_build={ADAPTER_BUILD}"
            )
        # Standalone build persists one auth file per account plus data/auth.json.
        if import_result.get("storage") != "filesystem":
            print(
                f"[grok-build-auth] WARN: unexpected standalone import storage="
                f"{import_result.get('storage')}"
            )
        imported_rows = [
            x for x in (import_result.get("imported") or []) if isinstance(x, dict)
        ]
        imported_ids = [str(x.get("id")) for x in imported_rows if x.get("id")]
        imported_accounts = [
            {"id": x.get("id"), "email": x.get("email") or email}
            for x in imported_rows
            if x.get("id") or x.get("email")
        ]
        sess["auth_json"] = import_result
        sess["imported_account_ids"] = imported_ids
        sess["imported_accounts"] = imported_accounts
        sess["oauth"] = {
            "path": "sso_to_auth_json",
            "access_token": (token.get("access_token") or "")[:20] + "...",
            "refresh_token": bool(token.get("refresh_token")),
            "email": email,
        }
        if bool(pipeline_cfg.get("auto_import_enabled")):
            _enqueue_pipeline_phase(sid, "import")
        else:
            _finish_pipeline_without_import(sid, pipeline_cfg)
        _enqueue_pipeline_phase(sid, "probe")
        return
    except _RegCancelled as exc:
        with _lock:
            cur = _sessions.get(sid) or sess
            cur["status"] = "cancelled"
            cur["message"] = str(exc) or "cancelled by user"
            cur["error"] = "cancelled"
            cur["cancel_requested"] = True
            cur["updated_at"] = _now()
            _sessions[sid] = cur
            _mirror_reg_sess(sid, cur)
        return
    except Exception as exc:  # noqa: BLE001
        try:
            update("error", f"failed: {exc}", error=str(exc))
        except _RegCancelled:
            with _lock:
                cur = _sessions.get(sid) or sess
                cur["status"] = "cancelled"
                cur["message"] = "cancelled by user"
                cur["error"] = "cancelled"
                cur["cancel_requested"] = True
                cur["updated_at"] = _now()
                _sessions[sid] = cur
                _mirror_reg_sess(sid, cur)
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
        with _lock:
            final_sess = dict(_sessions.get(sid) or sess or {})
            if sid in _sessions:
                _sessions[sid].pop("_receiver", None)
                _sessions[sid].pop("_client", None)
        # Single sessions write their own terminal task log. Batch sessions are
        # summarized once by the batch finalizer (avoids N noise rows).
        if final_sess and not final_sess.get("batch_id"):
            payload = _session_task_log_payload(final_sess)
            if payload.get("finished"):
                _record_register_task(
                    task_id=payload["task_id"] or sid,
                    summary=payload["summary"],
                    status=payload["status"],
                    ok=payload["ok"],
                    progress_done=payload["progress_done"],
                    progress_total=payload["progress_total"],
                    finished=True,
                    detail={**payload["detail"], "phase": "finished"},
                )



def _nonterminal_session_statuses() -> frozenset[str]:
    return frozenset(
        {
            "pending",
            "queued",
            "starting",
            "started",
            "running",
            "probing",
            "solving_turnstile",
            "waiting_email",
            "fetching_sso",
            "converting",
            "importing",
            "stopping",
        }
    )


def reclaim_orphaned_registration_sessions(
    *,
    stale_sec: float | None = None,
    batch_id: str | None = None,
) -> dict[str, Any]:
    """Mark abandoned non-terminal sessions as error so a batch can resume.

    After process restart / image upgrade, in-flight workers die but Redis still
    shows ``solving_turnstile`` etc. Those sessions never finish, and the
    batch runner is gone — registration appears "hung mid-way".
    """
    try:
        ttl = float(
            stale_sec
            if stale_sec is not None
            else (os.environ.get("GROK2API_REG_STALE_SEC", "180") or 180)
        )
    except (TypeError, ValueError):
        ttl = 180.0
    ttl = max(30.0, min(ttl, 3600.0))
    now = _now()
    nonterm = _nonterminal_session_statuses()
    want_batch = (batch_id or "").strip() or None

    reclaimed: list[dict[str, Any]] = []
    # Prefer durable Redis list when available.
    sessions: list[dict[str, Any]] = []
    if _reg_redis():
        try:
            from store import sessions_redis

            listed = sessions_redis.reg_sess_list() or []
            if isinstance(listed, list):
                sessions = [s for s in listed if isinstance(s, dict)]
        except Exception:
            sessions = []
    if not sessions:
        with _lock:
            sessions = [dict(v) for v in _sessions.values() if isinstance(v, dict)]

    for sess in sessions:
        sid = str(sess.get("id") or "").strip()
        if not sid:
            continue
        bid = str(sess.get("batch_id") or "").strip()
        if want_batch and bid != want_batch:
            continue
        st = str(sess.get("status") or "").strip().lower()
        if st in _TERMINAL_STATUSES or st not in nonterm:
            continue
        # Always reclaim if no local/remote runner can own it; use stale age as
        # a safety so we don't kill a still-running worker in the same process.
        age = now - float(sess.get("updated_at") or sess.get("created_at") or 0)
        # If this process holds an active runner for the batch, only reclaim
        # sessions older than ttl (true stalls). If no runner, reclaim all
        # non-terminal after a short grace (30s) so resume can proceed.
        has_runner = False
        if bid:
            with _lock:
                has_runner = bool(_active_batch_runners.get(bid))
            if not has_runner and _reg_redis():
                try:
                    from store.redis_client import get_str as redis_get

                    has_runner = bool(redis_get(_batch_runner_lock_key(bid)))
                except Exception:
                    has_runner = False
        min_age = ttl if has_runner else min(30.0, ttl)
        if age < min_age:
            continue
        msg = (
            f"reclaimed orphan session after {age:.0f}s "
            f"(status was {st}; runner_alive={has_runner})"
        )
        with _lock:
            cur = _sessions.get(sid) or dict(sess)
            prev = str(cur.get("status") or "").strip().lower()
            already_terminal = prev in _TERMINAL_STATUSES
            cur["status"] = "error"
            cur["error"] = msg
            cur["message"] = msg
            cur["cancel_requested"] = False
            cur["updated_at"] = now
            _sessions[sid] = cur
            _mirror_reg_sess(sid, dict(cur))
            # Count orphan as failed completion so batch remaining does not overshoot.
            if bid and not already_terminal:
                b = _batches.get(bid) or _load_reg_batch(bid) or {"id": bid}
                b = dict(b)
                b["fail_count"] = int(b.get("fail_count") or 0) + 1
                b["finished"] = int(b.get("finished") or 0) + 1
                b["updated_at"] = now
                if not b.get("message"):
                    b["message"] = "reclaimed orphan sessions"
                _batches[bid] = b
                _mirror_reg_batch(bid, dict(b))
        reclaimed.append(
            {
                "id": sid,
                "batch_id": bid,
                "prev_status": st,
                "age_sec": int(age),
                "email": sess.get("email"),
            }
        )
    return {
        "ok": True,
        "reclaimed": len(reclaimed),
        "stale_sec": ttl,
        "items": reclaimed[:100],
    }


def resume_registration_batch(
    batch_id: str,
    *,
    force: bool = False,
    reclaim_stale_sec: float | None = None,
) -> dict[str, Any]:
    """Reclaim orphan sessions and re-spawn the batch runner for remaining count.

    Used after process restart when Redis still shows status=running but no
    worker is actually spawning jobs.
    """
    bid = str(batch_id or "").strip()
    if not bid:
        return {"ok": False, "error": "missing batch id"}
    batch = _load_reg_batch(bid)
    if not batch:
        return {"ok": False, "error": "registration batch not found"}

    st = str(batch.get("status") or "").strip().lower()
    if st in {"done", "cancelled", "stopped"} and not force:
        return {
            "ok": False,
            "error": f"batch already terminal ({st}); pass force=true to resume",
            "batch_id": bid,
            "status": st,
        }
    if batch.get("cancel_requested") and not force:
        return {
            "ok": False,
            "error": "batch cancel_requested; clear stop or pass force=true",
            "batch_id": bid,
        }

    # Drop dead runner lock if our process does not own it (TTL may still hold).
    if force and _reg_redis():
        try:
            from store.redis_client import get_str as redis_get

            lock_k = _batch_runner_lock_key(bid)
            token = redis_get(lock_k)
            with _lock:
                local_alive = bool(_active_batch_runners.get(bid))
            if token and not local_alive:
                try:
                    from store.redis_client import compare_and_delete

                    compare_and_delete(lock_k, str(token))
                except Exception:
                    try:
                        # last resort: overwrite with short TTL empty marker then let expire
                        from store.redis_client import set_ex

                        set_ex(lock_k, "reclaimed", 1)
                    except Exception:
                        pass
        except Exception:
            pass

    reclaimed = reclaim_orphaned_registration_sessions(
        stale_sec=reclaim_stale_sec, batch_id=bid
    )

    count = int(batch.get("count") or 0)
    finished = int(batch.get("finished") or 0)
    # Prefer durable session list to compute remaining if counters lag.
    sids = list(batch.get("session_ids") or [])
    terminal = 0
    if sids and _reg_redis():
        try:
            from store import sessions_redis

            for sid in sids:
                sess = sessions_redis.reg_sess_get(str(sid)) or {}
                st_s = str(sess.get("status") or "").lower()
                if st_s in _TERMINAL_STATUSES:
                    terminal += 1
        except Exception:
            terminal = finished
    else:
        terminal = finished
    remaining = max(0, count - max(finished, terminal))
    if remaining <= 0:
        with _lock:
            b = _batches.get(bid) or dict(batch)
            b["status"] = "done" if int(b.get("fail_count") or 0) == 0 else "partial"
            b["runner_alive"] = False
            b["updated_at"] = _now()
            b["message"] = (
                f"resume: nothing remaining "
                f"(count={count} finished={finished} terminal={terminal})"
            )
            _batches[bid] = b
            _mirror_reg_batch(bid, dict(b))
        return {
            "ok": True,
            "batch_id": bid,
            "remaining": 0,
            "reclaimed": reclaimed.get("reclaimed") or 0,
            "message": "batch already complete",
            "status": (_load_reg_batch(bid) or {}).get("status"),
        }

    cfg = batch.get("reg_config") if isinstance(batch.get("reg_config"), dict) else {}
    provider = str(cfg.get("captcha_provider") or CAPTCHA_PROVIDER or "local").strip().lower()
    key = str(cfg.get("yescaptcha_key") or "").strip()
    proxy = str(cfg.get("proxy") or "").strip()
    workers = int(cfg.get("concurrency") or batch.get("concurrency") or DEFAULT_CONCURRENCY)
    configured_stagger = cfg.get("stagger_ms")
    if configured_stagger is None:
        configured_stagger = batch.get("stagger_ms")
    stagger = max(0, min(int(400 if configured_stagger is None else configured_stagger), 60_000))
    mail_provider = str(cfg.get("mail_provider") or "moemail").strip().lower()
    proxy_strategy = str(cfg.get("proxy_strategy") or "round_robin").strip().lower()

    # Clear cancel so spawn is allowed.
    with _lock:
        b = _batches.get(bid) or dict(batch)
        b["cancel_requested"] = False
        b["pause_requested"] = False
        if str(b.get("status") or "").lower() in {"stopping", "cancelled", "stopped", "error"}:
            b["status"] = "running"
        b["updated_at"] = _now()
        b["message"] = (
            f"resume requested remaining={remaining} "
            f"(reclaimed={reclaimed.get('reclaimed') or 0})"
        )
        _batches[bid] = b
        _mirror_reg_batch(bid, dict(b))

    spawned = _spawn_batch_runner(
        bid,
        remaining=remaining,
        concurrency=workers,
        stagger_ms=stagger,
        captcha_provider=provider,
        yescaptcha_key=key,
        proxy=proxy,
        proxy_strategy=proxy_strategy,
        moemail_api_key=cfg.get("moemail_api_key"),
        moemail_base_url=cfg.get("moemail_base_url"),
        prefix=cfg.get("prefix"),
        domain=cfg.get("domain"),
        expiry_ms=cfg.get("expiry_ms"),
        mail_provider=mail_provider,
        post_registration=cfg.get("post_registration") if isinstance(cfg.get("post_registration"), dict) else None,
        auto_tune_enabled=bool(cfg.get("auto_tune_enabled")),
    )
    out = {
        "ok": bool(spawned.get("ok")),
        "batch_id": bid,
        "remaining": remaining,
        "reclaimed": reclaimed.get("reclaimed") or 0,
        "reclaim": reclaimed,
        "spawn": spawned,
        "message": spawned.get("message") or spawned.get("error"),
    }
    if not out["ok"]:
        out["error"] = spawned.get("error") or "spawn failed"
    return out


def get_registration_performance_profile(
    provider: str | None = None,
    local_solver_url: str | None = None,
) -> dict[str, Any]:
    selected = str(provider or CAPTCHA_PROVIDER or "local").strip().lower()
    solver: dict[str, Any] = {}
    solver_threads = None
    if selected == "local":
        solver = probe_local_solver(local_solver_url, timeout=0.75)
        try:
            solver_threads = int(solver.get("thread") or 0) or None
        except (TypeError, ValueError):
            solver_threads = None
    profile = machine_profile(
        provider=selected,
        solver_threads=solver_threads,
        local_slots=_LOCAL_CAPTCHA_CONCURRENCY if selected == "local" else None,
        global_limit=_GLOBAL_REG_INFLIGHT_MAX,
    )
    profile["solver"] = solver
    return profile


def pause_registration_batch(batch_id: str) -> dict[str, Any]:
    """Pause batch scheduling while allowing already-running jobs to finish."""
    bid = str(batch_id or "").strip()
    if not bid:
        return {"ok": False, "error": "missing batch id"}
    batch = _load_reg_batch(bid)
    if not batch:
        return {"ok": False, "error": "registration batch not found"}
    status = str(batch.get("status") or "").lower()
    if status in {"done", "partial", "error"}:
        return {
            "ok": False,
            "error": f"batch already terminal ({status})",
            "batch_id": bid,
        }
    with _lock:
        current = _batches.get(bid) or dict(batch)
        current["pause_requested"] = True
        current["cancel_requested"] = False
        current["status"] = "pausing" if current.get("runner_alive") else "paused"
        current["message"] = "pause requested; waiting for active registrations to finish"
        current["updated_at"] = _now()
        _batches[bid] = current
        _mirror_reg_batch(bid, dict(current))
        out = dict(current)
    return {
        "ok": True,
        "batch_id": bid,
        "status": out["status"],
        "message": out["message"],
        "batch": out,
    }


def _schedule_probe_recheck(
    sid: str,
    config: dict[str, Any],
    *,
    current_attempt: int,
    next_attempt: int,
    delay: float,
) -> None:
    def run() -> None:
        sess = _load_reg_sess(sid) or {}
        probe = sess.get("probe") if isinstance(sess.get("probe"), dict) else {}
        if (
            str(probe.get("state") or "").lower() != "retry_pending"
            or int(probe.get("recheck_attempt") or 0) != current_attempt
            or _session_cancel_requested(sess)
        ):
            return
        group = _pipeline_group(sess)
        limit = max(
            1,
            min(
                MAX_CONCURRENCY,
                int(config.get("probe_concurrency") or config.get("pipeline_concurrency") or 1),
            ),
        )
        with _probe_group_slots(group, limit):
            _retry_probe_now(
                sid,
                config,
                manual_retry=False,
                recheck_attempt=next_attempt,
            )

    timer = threading.Timer(max(1.0, float(delay)), run)
    timer.daemon = True
    timer.name = f"gba-probe-recheck-{sid[-8:]}-{next_attempt}"
    timer.start()


def _retry_probe_now(
    session_id: str,
    post_registration: dict[str, Any] | None = None,
    *,
    manual_retry: bool = True,
    recheck_attempt: int = 0,
) -> dict[str, Any]:
    sid = str(session_id or "").strip()
    sess = _load_reg_sess(sid)
    if not sess:
        return {"ok": False, "error": "registration session not found"}
    account_ids = [str(x) for x in (sess.get("imported_account_ids") or []) if x]
    if not account_ids:
        return {"ok": False, "error": "该会话没有可测活的注册账号"}
    with _lock:
        current = _sessions.get(sid) or dict(sess)
        probe = dict(current.get("probe") or {})
        probe.update(
            {
                "state": "running",
                "queued": False,
                "position": 0,
                "recheck_attempt": max(0, int(recheck_attempt)),
            }
        )
        probe.pop("next_recheck_at", None)
        current["probe"] = probe
        message = "正在手动重试测活" if manual_retry else "正在执行队列测活"
        current["updated_at"] = _now()
        if manual_retry:
            _append_session_event(current, "probing", message, at=current["updated_at"])
        _sessions[sid] = current
        _mirror_reg_sess(sid, current)
    results: list[dict[str, Any]] = []
    config = dict(sess.get("_post_registration") or {})
    config.update(dict(post_registration or {}))
    try:
        import model_health

        model = str(config.get("model") or "grok-4.5")
        for account_id in account_ids:
            try:
                wait_pipeline_stagger("probe", config.get("probe_stagger_ms") or 0)
                response = model_health.probe_single_account(
                    account_id,
                    model,
                    auto_disable=True,
                    source="manual_retry" if manual_retry else "register_queue",
                )
                detail = response.get("result") if isinstance(response, dict) else {}
                if not isinstance(detail, dict):
                    detail = {}
                error = detail.get("error") or response.get("error") or ""
                results.append(
                    {
                        "account_id": account_id,
                        "ok": bool(response.get("ok")),
                        "model": detail.get("model") or model,
                        "status_code": detail.get("status_code"),
                        "latency_ms": detail.get("latency_ms"),
                        "retryable": bool(detail.get("retryable")),
                        "classification": detail.get("classification"),
                        "fallback": detail.get("fallback"),
                        "degraded": bool(detail.get("degraded")),
                        "chat_ready": detail.get("chat_ready"),
                        "message": detail.get("message"),
                        "error": str(error)[:180] if error else None,
                    }
                )
            except Exception as exc:  # noqa: BLE001
                results.append({"account_id": account_id, "ok": False, "error": str(exc)[:180]})
    except Exception as exc:  # noqa: BLE001
        results.append({"account_id": None, "ok": False, "error": str(exc)[:180]})
    uncertain = sum(1 for item in results if item.get("retryable") and not item.get("ok"))
    failed = sum(1 for item in results if not item.get("ok") and not item.get("retryable"))
    degraded = sum(1 for item in results if item.get("ok") and item.get("degraded"))
    summary = {
        "count": len(results),
        "ok": sum(1 for item in results if item.get("ok")),
        "fail": failed,
        "uncertain": uncertain,
        "degraded": degraded,
        "results": results,
        "state": "complete",
        "queued": False,
        "position": 0,
        "recheck_attempt": max(0, int(recheck_attempt)),
    }
    recheck_delay = None
    if uncertain:
        if recheck_attempt < len(PROBE_RECHECK_DELAYS):
            recheck_delay = PROBE_RECHECK_DELAYS[recheck_attempt]
            summary["state"] = "retry_pending"
            summary["next_recheck_at"] = _now() + recheck_delay
        else:
            summary["state"] = "uncertain"
    if manual_retry:
        summary["manual_retry"] = True
    with _lock:
        current = _sessions.get(sid) or dict(sess)
        current["probe"] = summary
        if summary["state"] == "retry_pending":
            message = (
                f"测活暂未确认：通过 {summary['ok']}，待复检 {summary['uncertain']}，"
                f"将在 {int(recheck_delay or 0)} 秒后自动复检"
            )
            event_status = "probe_retry_pending"
        elif summary["state"] == "uncertain":
            message = f"测活检测异常：通过 {summary['ok']}，无法确认 {summary['uncertain']}"
            event_status = "probe_uncertain"
        else:
            degraded_text = f"，其中轻量验证 {summary['degraded']}" if summary["degraded"] else ""
            message = (
                f"手动测活完成：通过 {summary['ok']}，失败 {summary['fail']}{degraded_text}"
                if manual_retry
                else f"队列测活完成：通过 {summary['ok']}，失败 {summary['fail']}{degraded_text}"
            )
            event_status = "probe_complete"
        current["updated_at"] = _now()
        _append_session_event(current, event_status, message, at=current["updated_at"])
        _sessions[sid] = current
        _mirror_reg_sess(sid, current)
    if recheck_delay is not None:
        _schedule_probe_recheck(
            sid,
            config,
            current_attempt=max(0, int(recheck_attempt)),
            next_attempt=max(0, int(recheck_attempt)) + 1,
            delay=recheck_delay,
        )
    return {
        "ok": summary["fail"] == 0 and summary["uncertain"] == 0,
        "session_id": sid,
        "probe": summary,
    }


def retry_registration_probe(
    session_id: str, post_registration: dict[str, Any] | None = None
) -> dict[str, Any]:
    sid = str(session_id or "").strip()
    sess = _load_reg_sess(sid)
    if not sess:
        return {"ok": False, "error": "registration session not found"}
    probe = sess.get("probe") if isinstance(sess.get("probe"), dict) else {}
    if str(probe.get("state") or "").lower() in {"running", "retry_pending"}:
        return {"ok": True, "session_id": sid, "already_running": True}
    threading.Thread(
        target=_retry_probe_now,
        args=(sid, post_registration),
        daemon=True,
        name=f"gba-retry-probe-{sid[-8:]}",
    ).start()
    return {"ok": True, "session_id": sid, "scheduled": True}


def retry_registration_batch_probe(
    batch_id: str, post_registration: dict[str, Any] | None = None
) -> dict[str, Any]:
    bid = str(batch_id or "").strip()
    batch = _load_reg_batch(bid)
    if not batch:
        return {"ok": False, "error": "registration batch not found"}
    candidates: list[str] = []
    for sid in batch.get("session_ids") or []:
        sess = _load_reg_sess(str(sid)) or {}
        probe = sess.get("probe") if isinstance(sess.get("probe"), dict) else {}
        if (
            str(probe.get("state") or "").lower() not in {"running", "retry_pending"}
            and (sess.get("imported_account_ids") or [])
            and (
                not probe
                or int(probe.get("fail") or 0) > 0
                or int(probe.get("uncertain") or 0) > 0
            )
        ):
            candidates.append(str(sid))

    def run() -> None:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        config = dict(post_registration or {})
        limit = max(
            1,
            min(
                MAX_CONCURRENCY,
                int(config.get("probe_concurrency") or config.get("pipeline_concurrency") or 1),
            ),
        )
        with ThreadPoolExecutor(max_workers=limit, thread_name_prefix="gba-manual-probe") as pool:
            futures = [pool.submit(_retry_probe_now, sid, post_registration) for sid in candidates]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass

    if candidates:
        threading.Thread(target=run, daemon=True, name=f"gba-retry-probe-{bid[-8:]}").start()
    return {"ok": True, "batch_id": bid, "scheduled": len(candidates)}


def _retry_import_now(
    session_id: str,
    post_registration: dict[str, Any] | None = None,
    *,
    manual_retry: bool = True,
) -> dict[str, Any]:
    sid = str(session_id or "").strip()
    sess = _load_reg_sess(sid)
    if not sess:
        return {"ok": False, "error": "registration session not found"}
    account_ids = [str(x) for x in (sess.get("imported_account_ids") or []) if x]
    if not account_ids:
        return {"ok": False, "error": "该会话没有可导入的注册账号"}
    config = dict(sess.get("_post_registration") or {})
    config.update(dict(post_registration or {}))
    target = str(config.get("target") or "sub2api").lower()
    with _lock:
        current = _sessions.get(sid) or dict(sess)
        current["status"] = "auto_importing"
        current["auto_import"] = {
            "enabled": True,
            "target": target,
            "ok": None,
            "skipped": False,
            "queued": False,
            "manual_retry": bool(manual_retry),
        }
        current["message"] = (
            f"正在手动重试导入 {'CPA' if target == 'cpa' else 'Sub2API'}"
            if manual_retry
            else f"正在执行队列导入 {'CPA' if target == 'cpa' else 'Sub2API'}"
        )
        current["updated_at"] = _now()
        _append_session_event(
            current, current["status"], current["message"], at=current["updated_at"]
        )
        _sessions[sid] = current
        _mirror_reg_sess(sid, current)
    results: list[dict[str, Any]] = []
    try:
        import model_health
        from account_pipeline import import_account

        for account_id in account_ids:
            try:
                record = model_health._load_record(account_id)
                wait_pipeline_stagger(
                    "import", config.get("import_stagger_ms") or 0
                )
                response = import_account(record, config)
                results.append(
                    {
                        "ok": bool(response.get("ok")),
                        "status_code": response.get("status_code"),
                        "error": str(response.get("error") or "")[:220] or None,
                    }
                )
            except Exception as exc:  # noqa: BLE001
                results.append({"ok": False, "error": str(exc)[:220]})
    except Exception as exc:  # noqa: BLE001
        results.append({"ok": False, "error": str(exc)[:220]})
    ok_count = sum(1 for item in results if item.get("ok"))
    fail_count = sum(1 for item in results if not item.get("ok"))
    first_error = next((item.get("error") for item in results if item.get("error")), None)
    auto_import = {
        "enabled": True,
        "target": target,
        "ok": fail_count == 0 and ok_count > 0,
        "skipped": False,
        "count": len(results),
        "imported": ok_count,
        "failed": fail_count,
        "error": first_error,
    }
    if manual_retry:
        auto_import["manual_retry"] = True
    with _lock:
        current = _sessions.get(sid) or dict(sess)
        current["auto_import"] = auto_import
        current["status"] = "imported"
        current["message"] = (
            f"手动导入完成：成功 {ok_count}，失败 {fail_count}"
            if manual_retry
            else f"队列导入完成：成功 {ok_count}，失败 {fail_count}"
        )
        current["pipeline_queue"] = {
            "phase": "done",
            "position": 0,
            "concurrency": int(config.get("pipeline_concurrency") or 1),
        }
        current["updated_at"] = _now()
        _append_session_event(
            current, current["status"], current["message"], at=current["updated_at"]
        )
        _sessions[sid] = current
        _mirror_reg_sess(sid, current)
    return {"ok": bool(auto_import["ok"]), "session_id": sid, "auto_import": auto_import}


def retry_registration_import(
    session_id: str, post_registration: dict[str, Any] | None = None
) -> dict[str, Any]:
    sid = str(session_id or "").strip()
    sess = _load_reg_sess(sid)
    if not sess:
        return {"ok": False, "error": "registration session not found"}
    status = str(sess.get("status") or "").lower()
    if status in {"auto_importing", "import_queued"}:
        return {
            "ok": True,
            "session_id": sid,
            "already_running": True,
            "queued": status == "import_queued",
        }
    threading.Thread(
        target=_retry_import_now,
        args=(sid, post_registration),
        daemon=True,
        name=f"gba-retry-import-{sid[-8:]}",
    ).start()
    return {"ok": True, "session_id": sid, "scheduled": True}


def retry_registration_batch_import(
    batch_id: str, post_registration: dict[str, Any] | None = None
) -> dict[str, Any]:
    bid = str(batch_id or "").strip()
    batch = _load_reg_batch(bid)
    if not batch:
        return {"ok": False, "error": "registration batch not found"}
    candidates: list[str] = []
    for sid in batch.get("session_ids") or []:
        sess = _load_reg_sess(str(sid)) or {}
        status = str(sess.get("status") or "").lower()
        imported = sess.get("auto_import") if isinstance(sess.get("auto_import"), dict) else {}
        if (
            status not in {"auto_importing", "import_queued"}
            and bool(sess.get("imported_account_ids") or [])
            and imported.get("ok") is not True
        ):
            candidates.append(str(sid))

    def run() -> None:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        config = dict(post_registration or {})
        limit = max(
            1,
            min(
                MAX_CONCURRENCY,
                int(config.get("import_concurrency") or config.get("pipeline_concurrency") or 1),
            ),
        )
        with ThreadPoolExecutor(max_workers=limit, thread_name_prefix="gba-manual-import") as pool:
            futures = [pool.submit(_retry_import_now, sid, post_registration) for sid in candidates]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass

    if candidates:
        threading.Thread(target=run, daemon=True, name=f"gba-retry-import-{bid[-8:]}").start()
    return {"ok": True, "batch_id": bid, "scheduled": len(candidates)}


def reclaim_orphaned_registration_batches(
    *,
    stale_sec: float | None = None,
    auto_resume: bool = True,
    max_batches: int | None = None,
) -> dict[str, Any]:
    """On startup: reclaim orphan sessions and optionally resume open batches."""
    try:
        ttl = float(
            stale_sec
            if stale_sec is not None
            else (os.environ.get("GROK2API_REG_STALE_SEC", "120") or 120)
        )
    except (TypeError, ValueError):
        ttl = 120.0
    if max_batches is None:
        try:
            max_batches = int(os.environ.get("GROK2API_REG_AUTO_RESUME_MAX", "1") or 1)
        except (TypeError, ValueError):
            max_batches = 1
    max_batches = max(0, min(10, int(max_batches)))

    # First pass: mark dead in-flight sessions.
    sess_result = reclaim_orphaned_registration_sessions(stale_sec=ttl)

    batches: list[dict[str, Any]] = []
    if _reg_redis():
        try:
            from store import sessions_redis

            listed = sessions_redis.reg_batch_list() or []
            if isinstance(listed, list):
                batches = [b for b in listed if isinstance(b, dict)]
        except Exception:
            batches = []
    if not batches:
        with _lock:
            batches = [dict(v) for v in _batches.values() if isinstance(v, dict)]

    resumed: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    # Newest first.
    batches = sorted(
        batches, key=lambda b: float(b.get("updated_at") or b.get("created_at") or 0), reverse=True
    )
    for b in batches:
        if len(resumed) >= max(0, int(max_batches)):
            break
        bid = str(b.get("id") or "").strip()
        if not bid:
            continue
        st = str(b.get("status") or "").strip().lower()
        if st not in {"running", "starting", "stopping", "partial"} and not (
            st == "error" and int(b.get("finished") or 0) < int(b.get("count") or 0)
        ):
            continue
        if b.get("cancel_requested") and st in {"stopping", "cancelled", "stopped"}:
            skipped.append({"batch_id": bid, "reason": "cancel_requested", "status": st})
            continue
        # Skip only if THIS process has a live runner. Redis locks from a dead
        # process (image restart) must not block auto-resume forever — force
        # clear them when no local runner owns the batch.
        has_local = False
        with _lock:
            has_local = bool(_active_batch_runners.get(bid))
        if has_local:
            skipped.append({"batch_id": bid, "reason": "local_runner_alive", "status": st})
            continue
        if _reg_redis():
            try:
                from store.redis_client import get_str as redis_get

                token = redis_get(_batch_runner_lock_key(bid))
                if token:
                    # Stale lock from previous process — clear so resume can claim.
                    try:
                        from store.redis_client import compare_and_delete

                        compare_and_delete(_batch_runner_lock_key(bid), str(token))
                    except Exception:
                        try:
                            from store.redis_client import set_ex

                            set_ex(_batch_runner_lock_key(bid), "reclaimed", 1)
                        except Exception:
                            pass
            except Exception:
                pass
        count = int(b.get("count") or 0)
        finished = int(b.get("finished") or 0)
        if count > 0 and finished >= count:
            skipped.append({"batch_id": bid, "reason": "already_finished", "status": st})
            continue
        if not auto_resume:
            skipped.append({"batch_id": bid, "reason": "auto_resume_disabled", "status": st})
            continue
        r = resume_registration_batch(bid, force=True, reclaim_stale_sec=ttl)
        resumed.append(r)

    return {
        "ok": True,
        "sessions_reclaimed": sess_result.get("reclaimed") or 0,
        "session_reclaim": sess_result,
        "batches_resumed": sum(1 for r in resumed if r.get("ok")),
        "resumed": resumed,
        "skipped": skipped[:20],
    }


def stop_registration_session(session_id: str) -> dict[str, Any]:
    """Request cooperative cancel for one registration session."""
    sid = str(session_id or "").strip()
    if not sid:
        return {"ok": False, "error": "missing session id"}
    sess = _load_reg_sess(sid)
    if not sess:
        return {"ok": False, "error": "registration session not found"}
    st = str(sess.get("status") or "").lower()
    if st in _TERMINAL_STATUSES:
        return {
            "ok": True,
            "id": sid,
            "status": st,
            "already_terminal": True,
            "message": sess.get("message") or st,
        }
    with _lock:
        cur = _sessions.get(sid) or dict(sess)
        cur["cancel_requested"] = True
        cur["status"] = "stopping"
        cur["message"] = "stop requested; waiting for worker to exit"
        cur["updated_at"] = _now()
        _sessions[sid] = cur
        _mirror_reg_sess(sid, cur)
        out = _compact_session(cur)
    return {"ok": True, "id": sid, **out}


def stop_registration_batch(batch_id: str) -> dict[str, Any]:
    """Request cooperative cancel for every non-terminal session in a batch."""
    bid = str(batch_id or "").strip()
    if not bid:
        return {"ok": False, "error": "missing batch id"}
    batch = _load_reg_batch(bid)
    if not batch:
        return {"ok": False, "error": "registration batch not found"}

    # Mark batch cancelled FIRST so spawner/workers observe stop even before
    # individual session mirrors catch up (multi-worker / Redis path).
    with _lock:
        b = _batches.get(bid) or dict(batch)
        b["cancel_requested"] = True
        if str(b.get("status") or "").lower() not in (
            "done",
            "partial",
            "error",
            "cancelled",
            "stopped",
        ):
            b["status"] = "stopping"
        b["message"] = "stop requested; signalling sessions"
        b["updated_at"] = _now()
        _batches[bid] = b
        _mirror_reg_batch(bid, dict(b))
        sids = list(b.get("session_ids") or [])

    stopped: list[str] = []
    already: list[str] = []
    missing: list[str] = []
    for sid in sids:
        r = stop_registration_session(str(sid))
        if not r.get("ok"):
            missing.append(str(sid))
            continue
        if r.get("already_terminal"):
            already.append(str(sid))
        else:
            stopped.append(str(sid))

    with _lock:
        b = _batches.get(bid) or dict(batch)
        b["cancel_requested"] = True
        if str(b.get("status") or "").lower() not in (
            "done",
            "partial",
            "error",
            "cancelled",
            "stopped",
        ):
            b["status"] = "stopping"
        b["message"] = (
            f"stop requested: stopping={len(stopped)} "
            f"already_done={len(already)} missing={len(missing)}"
        )
        b["updated_at"] = _now()
        _batches[bid] = b
        _mirror_reg_batch(bid, dict(b))
        out = dict(b)
    return {
        "ok": True,
        "batch_id": bid,
        "stopped": stopped,
        "already_terminal": already,
        "missing": missing,
        "message": out.get("message") or "stop requested",
        "batch": out,
    }


def stop_all_active_registrations() -> dict[str, Any]:
    """Stop every non-terminal registration session currently visible."""
    listed = list_registration_sessions()
    sessions = list(listed.get("sessions") or [])
    stopped = []
    already = []
    for s in sessions:
        sid = str(s.get("id") or "")
        if not sid:
            continue
        r = stop_registration_session(sid)
        if r.get("already_terminal"):
            already.append(sid)
        elif r.get("ok"):
            stopped.append(sid)
    # Also mark running batches as stopping.
    for b in list(listed.get("batches") or []):
        bid = str(b.get("id") or b.get("batch_id") or "")
        if not bid:
            continue
        st = str(b.get("status") or b.get("batch_status") or "").lower()
        if st in ("done", "partial", "error", "cancelled", "stopped"):
            continue
        try:
            stop_registration_batch(bid)
        except Exception:
            pass
    return {
        "ok": True,
        "stopped": stopped,
        "already_terminal": already,
        "stopped_count": len(stopped),
        "already_count": len(already),
    }


def list_registration_sessions() -> dict[str, Any]:
    _clean_old_sessions()
    # Merge Redis-visible sessions/batches so other workers can observe progress.
    if _reg_redis():
        try:
            from store import sessions_redis

            for remote in sessions_redis.reg_sess_list():
                sid = str(remote.get("id") or "")
                if not sid:
                    continue
                with _lock:
                    if sid not in _sessions:
                        _sessions[sid] = remote
                    else:
                        # Prefer newer updated_at, but keep local process-only fields.
                        local = _sessions[sid]
                        if float(remote.get("updated_at") or 0) >= float(
                            local.get("updated_at") or 0
                        ):
                            merged = {**local, **remote}
                            for k, v in local.items():
                                if isinstance(k, str) and k.startswith("_") and k not in remote:
                                    merged[k] = v
                            _sessions[sid] = merged
            for remote_b in sessions_redis.reg_batch_list():
                bid = str(remote_b.get("id") or remote_b.get("batch_id") or "")
                if not bid:
                    continue
                with _lock:
                    if bid not in _batches:
                        _batches[bid] = remote_b
                    else:
                        local_b = _batches[bid]
                        if float(remote_b.get("updated_at") or 0) >= float(
                            local_b.get("updated_at") or 0
                        ):
                            # Union session_ids so late workers don't drop early ones.
                            ids = list(local_b.get("session_ids") or [])
                            for x in remote_b.get("session_ids") or []:
                                if x not in ids:
                                    ids.append(x)
                            merged_b = {**local_b, **remote_b, "session_ids": ids}
                            _batches[bid] = merged_b
        except Exception:
            pass
    with _lock:
        sessions = [_compact_session(s) for s in _sessions.values()]
        sessions.sort(
            key=lambda s: float(s.get("updated_at") or s.get("created_at") or 0),
            reverse=True,
        )
        batches = []
        for b in _batches.values():
            sids = list(b.get("session_ids") or [])
            stats = _batch_stats(sids, batch=b)
            # If all observed sessions cancelled, surface batch as cancelled.
            if sids and stats.get("running") == 0 and stats.get("cancelled", 0) > 0:
                if (
                    stats.get("imported", 0) == 0
                    and stats.get("error", 0) == 0
                    and stats.get("missing", 0) == 0
                ):
                    stats["batch_status"] = "cancelled"
            item = {**b, **stats}
            item.pop("reg_config", None)
            # Align top-level status with computed batch_status for UI restore filters.
            bst = str(stats.get("batch_status") or "").lower()
            cur = str(b.get("status") or "").lower()
            if bst and (
                cur in ("", "running", "starting")
                or (bst in ("done", "partial", "error", "cancelled", "stopped") and stats.get("running", 0) == 0)
            ):
                if cur != "stopping" or stats.get("running", 0) == 0:
                    item["status"] = bst if bst != "running" or cur != "stopping" else cur
            batches.append(item)
        batches.sort(
            key=lambda b: float(b.get("updated_at") or b.get("created_at") or 0),
            reverse=True,
        )
    return {
        "sessions": sessions,
        "batches": batches,
        "active": sum(
            1
            for s in sessions
            if str(s.get("status") or "").lower() not in _TERMINAL_STATUSES
        ),
    }


def reset_registration_monitor() -> dict[str, Any]:
    """Clear the current monitor round without deleting saved account files."""
    with _lock:
        active_sessions = [
            sid
            for sid, session in _sessions.items()
            if str(session.get("status") or "").lower() not in _TERMINAL_STATUSES
        ]
        active_batches = [
            bid
            for bid, batch in _batches.items()
            if str(batch.get("status") or "").lower()
            not in {"paused", "done", "partial", "error", "cancelled", "stopped"}
        ]
        active_runners = [bid for bid, running in _active_batch_runners.items() if running]
        if active_sessions or active_batches or active_runners:
            return {
                "ok": False,
                "error": "仍有任务正在运行，请先暂停或停止后再清除本轮任务",
            }
        session_count = len(_sessions)
        batch_count = len(_batches)
        _sessions.clear()
        _batches.clear()
        _active_batch_runners.clear()
    with _pipeline_queue_lock:
        _pipeline_queues.clear()
    return {
        "ok": True,
        "sessions_cleared": session_count,
        "batches_cleared": batch_count,
    }


def get_registration_session(
    sid: str, *, include_auth_json: bool = False
) -> dict[str, Any] | None:
    sess = _load_reg_sess(sid)
    if not sess:
        return None
    out = dict(sess)
    for key in list(out):
        if isinstance(key, str) and key.startswith("_"):
            out.pop(key, None)
    out.pop("password", None)
    out.pop("yescaptcha_key", None)
    if not include_auth_json:
        out.pop("auth_json", None)
    return out


def _batch_stats(
    session_ids: list[str],
    *,
    batch: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compute batch counters from live sessions.

    Missing sessions (TTL expired / not mirrored) are *not* treated as running —
    that previously made finished historical batches look active after Redis
    session keys aged out. When no live sessions remain, fall back to the
    persisted batch status/message counters.
    """
    imported = error = running = cancelled = missing = 0
    for sid in session_ids:
        sess = _load_reg_sess(sid)
        if not sess:
            missing += 1
            continue
        st = str(sess.get("status") or "").lower()
        if st in ("imported", "success", "completed"):
            imported += 1
        elif st in ("cancelled", "stopped"):
            cancelled += 1
        elif st in ("error", "failed", "expired", "protocol_error", "protocol_blocked"):
            error += 1
        else:
            running += 1

    total = len(session_ids)
    observed = imported + error + cancelled + running
    done = imported + error + cancelled
    target = 0
    if isinstance(batch, dict):
        try:
            target = int(batch.get("count") or 0)
        except Exception:
            target = 0
    if target <= 0:
        target = total

    status = "running"
    if observed == 0:
        # No live sessions left — trust last mirrored batch status if terminal.
        stored = ""
        if isinstance(batch, dict):
            stored = str(batch.get("batch_status") or batch.get("status") or "").lower()
        if stored in ("done", "partial", "error", "cancelled", "stopped"):
            status = stored
            # Prefer stored counters when present so UI keeps final totals.
            try:
                imported = int(batch.get("imported") or imported)
            except Exception:
                pass
            try:
                error = int(batch.get("error") or error)
            except Exception:
                pass
            try:
                cancelled = int(batch.get("cancelled") or cancelled)
            except Exception:
                pass
            try:
                done = int(batch.get("done") or (imported + error + cancelled))
            except Exception:
                done = imported + error + cancelled
            running = 0
        elif total and missing >= total:
            # All session keys gone and no terminal marker.
            # Prefer counters / message fragments; never keep a fully-missing
            # batch as "running" forever (ghost cards after Redis TTL).
            msg = str((batch or {}).get("message") or "")
            if isinstance(batch, dict):
                try:
                    imported = int(batch.get("imported") or imported or 0)
                except Exception:
                    pass
                try:
                    error = int(batch.get("error") or error or 0)
                except Exception:
                    pass
                try:
                    cancelled = int(batch.get("cancelled") or cancelled or 0)
                except Exception:
                    pass
            # Parse "ok=N fail=M" style messages written by the spawner.
            if imported == 0 and error == 0 and cancelled == 0 and msg:
                import re as _re

                m_ok = _re.search(r"ok\s*=\s*(\d+)", msg)
                m_fail = _re.search(r"fail\s*=\s*(\d+)", msg)
                if m_ok:
                    try:
                        imported = int(m_ok.group(1))
                    except Exception:
                        pass
                if m_fail:
                    try:
                        error = int(m_fail.group(1))
                    except Exception:
                        pass
            done = imported + error + cancelled
            if cancelled and not imported and not error:
                status = "cancelled"
            elif imported and not error and not cancelled:
                status = "done"
            elif imported:
                status = "partial"
            elif error:
                status = "error"
            elif stored in ("stopping",):
                status = "stopped"
            else:
                status = "done"
            running = 0
        else:
            status = "running"
    elif done >= max(target, total) and running == 0:
        if cancelled and not imported and not error:
            status = "cancelled"
        elif error == 0 and cancelled == 0:
            status = "done"
        elif imported:
            status = "partial"
        else:
            status = "error"
    elif running == 0 and missing > 0 and done > 0 and observed < total:
        # Partial visibility (some sessions expired) but nothing live.
        if imported and (error or cancelled or missing):
            status = "partial"
        elif imported and not error and not cancelled:
            status = "done"
        elif cancelled and not imported and not error:
            status = "cancelled"
        elif error and not imported:
            status = "error"
        else:
            status = "partial"
    elif total and (imported or error or cancelled) and running:
        status = "running"
    elif running:
        status = "running"

    # Honour explicit cooperative stop marker on the batch itself.
    if isinstance(batch, dict):
        bst = str(batch.get("status") or "").lower()
        if bst in ("pausing", "paused"):
            status = "pausing" if running else "paused"
        elif bst in ("stopping", "cancelled", "stopped") and running == 0:
            if status == "running":
                status = "cancelled" if cancelled or bst != "stopping" else "stopped"
        if bst == "stopping" and running:
            status = "running"

    return {
        "total": max(total, target),
        "imported": imported,
        "error": error,
        "cancelled": cancelled,
        "running": running,
        "missing": missing,
        "done": done,
        "batch_status": status,
    }


def get_registration_batch(batch_id: str) -> dict[str, Any] | None:
    b = _load_reg_batch(batch_id)
    if not b:
        return None
    sids = list(b.get("session_ids") or [])
    stats = _batch_stats(sids, batch=b)
    # Keep response bounded for large batches: newest sessions first for UI.
    MAX_BATCH_SESSIONS = 120
    sessions = []
    for s in sids[-MAX_BATCH_SESSIONS:]:
        sess = _load_reg_sess(s)
        if sess:
            sessions.append(_compact_session(sess))
    # Prefer recency if timestamps available.
    try:
        sessions.sort(
            key=lambda s: float(s.get("updated_at") or s.get("created_at") or 0),
            reverse=True,
        )
    except Exception:
        pass
    out = {**b, **stats, "sessions": sessions}
    out.pop("reg_config", None)
    # Surface effective status for older UIs that only read `status`.
    if stats.get("batch_status"):
        # Don't clobber an explicit cooperative "stopping" marker while workers live.
        if str(b.get("status") or "").lower() != "stopping" or stats.get("running", 0) == 0:
            if stats.get("running", 0) == 0 or str(b.get("status") or "").lower() in (
                "",
                "running",
                "starting",
            ):
                out["status"] = stats["batch_status"]
    return out


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main() -> int:
    print("grok-build-auth adapter for grokcli-2api")
    result = start_registration()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if not result.get("ok"):
        return 1

    sid = result["id"]
    deadline = time.time() + 600
    while time.time() < deadline:
        sess = get_registration_session(sid, include_auth_json=True)
        if not sess:
            print("session disappeared", file=sys.stderr)
            return 1
        status = sess.get("status")
        print(f"[{time.strftime('%H:%M:%S')}] {status}: {sess.get('message')}")
        if status in ("imported", "error"):
            print(json.dumps(sess, ensure_ascii=False, indent=2))
            return 0 if status == "imported" else 1
        time.sleep(5)

    print("timeout", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
