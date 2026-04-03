"""
guard_tool decorator — sync and async, stateless session enforcement.

SESSION STATE FIX: In-memory dict is gone. Session state is now STATELESS
by design: each call is evaluated independently unless a Redis store is
passed via session_store=. This is correct for multi-worker deployments.

If you need cross-worker session budgets, pass a RedisSessionStore instance.
The in-process store (InProcessSessionStore) is provided for single-process
use and testing only.
"""
import dataclasses
import functools
import inspect
import json
import logging
import threading
import warnings
from typing import Callable, Optional

from .exceptions import ZerofalseSecurity, ZerofalseWarning
from .models import ScanResult

logger = logging.getLogger("zerofalse")

MAX_BLOCKS_PER_SESSION = 10

# ── Thread-safe singleton clients ────────────────────────────────────────────
_sync_client = None
_async_client = None
_lock = threading.Lock()


def _get_sync():
    global _sync_client
    if _sync_client is None:
        with _lock:
            if _sync_client is None:
                from .client import ZerofalseClient
                _sync_client = ZerofalseClient()
    return _sync_client


def _get_async():
    global _async_client
    if _async_client is None:
        with _lock:
            if _async_client is None:
                from .client import AsyncZerofalseClient
                _async_client = AsyncZerofalseClient()
    return _async_client


# ── Session stores ────────────────────────────────────────────────────────────

class InProcessSessionStore:
    """Single-process only. Wiped on restart. Use for dev/testing."""
    def __init__(self):
        self._data: dict = {}
        self._lock = threading.Lock()

    def get(self, sid: str) -> dict:
        with self._lock:
            return dict(self._data.get(sid, {"count": 0, "last_threat": None, "call_counts": {}}))

    def set(self, sid: str, state: dict) -> None:
        with self._lock:
            self._data[sid] = dict(state)


class StatelessSessionStore:
    """
    No cross-call memory. Each call is independent.
    Session budget cannot be enforced across calls/workers.
    Safe for multi-worker. Default for production.
    """
    def get(self, sid: str) -> dict:
        return {"count": 0, "last_threat": None, "call_counts": {}}

    def set(self, sid: str, state: dict) -> None:
        pass  # intentionally no-op


_default_store = StatelessSessionStore()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _build_blocked_json(result: ScanResult, tool_name: str, block_count: int) -> str:
    return json.dumps({
        "status": "blocked", "decision": "BLOCK",
        "threat_type": result.threat_type, "pattern_id": result.pattern_id,
        "reason": result.description,
        "evidence": result.evidence[0] if result.evidence else None,
        "action_taken": result.action_taken,
        "hint": result.hint,
        "safe_alternatives": result.safe_alternatives,
        "retry_allowed": result.retry_allowed,
        "session_block_count": block_count,
        "risk_score": round(result.risk_score, 3),
        "latency_ms": round(result.latency_ms, 2),
        "scan_id": result.scan_id,
    }, indent=2)


def _apply_session_logic(result: ScanResult, sess: dict, tool_name: str):
    """Returns updated (sess, result) with hard-stop conditions applied."""
    if result.decision != "block":
        if result.decision == "allow":
            sess = dict(sess)
            sess["last_threat"] = None
        return sess, result

    sess = dict(sess)
    sess["count"] = sess.get("count", 0) + 1
    counts = dict(sess.get("call_counts") or {})
    call_count = counts.get(tool_name, 0)
    counts[tool_name] = call_count + 1
    sess["call_counts"] = counts

    # Prompt injection on retry → force no-retry
    if result.threat_type == "prompt_injection" and call_count >= 1:
        result = dataclasses.replace(
            result, retry_allowed=False,
            hint="Prompt injection detected on retry. Session must be terminated.",
        )

    # Same threat twice in a row → force no-retry
    if sess.get("last_threat") == result.threat_type and result.threat_type:
        result = dataclasses.replace(result, retry_allowed=False)

    sess["last_threat"] = result.threat_type
    return sess, result


def _raise_blocked(result: ScanResult, tool_name: str, count: int, return_json: bool):
    structured = _build_blocked_json(result, tool_name, count) if return_json else None
    logger.error(
        "BLOCKED tool=%s risk=%.0f%% threat=%s scan_id=%s retry=%s",
        tool_name, result.risk_score * 100, result.threat_type, result.scan_id, result.retry_allowed,
    )
    raise ZerofalseSecurity(
        tool_name=tool_name, risk_score=result.risk_score,
        threat_type=result.threat_type or "unknown",
        evidence=result.evidence, scan_id=result.scan_id,
        structured_response=structured,
    )


def _handle_warn(result: ScanResult, tool_name: str, on_warn: str, callback: Optional[Callable]):
    msg = f"[ZEROFALSE WARN] tool={tool_name} risk={result.risk_score:.0%} {result.description}"
    if callback:
        try:
            callback(result, tool_name)
        except Exception as e:
            logger.warning("on_warn_callback error: %s", e)
    if on_warn == "raise":
        warnings.warn(msg, ZerofalseWarning, stacklevel=3)
    else:
        logger.warning(msg)
        if result.hint:
            logger.warning("[ZEROFALSE HINT] %s", result.hint)


# ── Main decorator ────────────────────────────────────────────────────────────

def guard_tool(
    _func=None, *,
    client=None,
    agent_id: str = "default",
    session_id: str = "default",
    on_warn: str = "log",
    on_warn_callback: Optional[Callable] = None,
    return_json_on_block: bool = True,
    session_store=None,
):
    """
    Decorator for AI agent tool functions.

    Works on both sync and async functions:
      - sync  → ZerofalseClient (sync httpx, no event-loop blocking)
      - async → AsyncZerofalseClient (async httpx, non-blocking)

    Args:
        client:              Override default client.
        agent_id:            Agent identifier.
        session_id:          Session identifier for budget tracking.
        on_warn:             "log" or "raise".
        on_warn_callback:    Optional callable(result, tool_name) on WARN.
        return_json_on_block: ZerofalseSecurity.structured_response contains JSON.
        session_store:       Custom session store. Defaults to StatelessSessionStore.
    """
    store = session_store or _default_store

    def decorator(func):
        is_async = inspect.iscoroutinefunction(func)

        if is_async:
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                _client = client or _get_async()
                sig = inspect.signature(func)
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                tool_args = dict(bound.arguments)

                sess = store.get(session_id)
                if sess["count"] >= MAX_BLOCKS_PER_SESSION:
                    _raise_budget_exceeded(func.__name__, session_id, sess["count"])

                result = await _client.scan_tool_call(
                    tool_name=func.__name__, arguments=tool_args,
                    agent_id=agent_id, session_id=session_id,
                )
                sess, result = _apply_session_logic(result, sess, func.__name__)
                store.set(session_id, sess)

                if result.decision == "block":
                    _raise_blocked(result, func.__name__, sess["count"], return_json_on_block)
                if result.decision == "warn":
                    _handle_warn(result, func.__name__, on_warn, on_warn_callback)
                return await func(*args, **kwargs)

            return async_wrapper

        else:
            @functools.wraps(func)
            def sync_wrapper(*args, **kwargs):
                _client = client or _get_sync()
                sig = inspect.signature(func)
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                tool_args = dict(bound.arguments)

                sess = store.get(session_id)
                if sess["count"] >= MAX_BLOCKS_PER_SESSION:
                    _raise_budget_exceeded(func.__name__, session_id, sess["count"])

                result = _client.scan_tool_call(
                    tool_name=func.__name__, arguments=tool_args,
                    agent_id=agent_id, session_id=session_id,
                )
                sess, result = _apply_session_logic(result, sess, func.__name__)
                store.set(session_id, sess)

                if result.decision == "block":
                    _raise_blocked(result, func.__name__, sess["count"], return_json_on_block)
                if result.decision == "warn":
                    _handle_warn(result, func.__name__, on_warn, on_warn_callback)
                return func(*args, **kwargs)

            return sync_wrapper

    if _func is not None:
        return decorator(_func)
    return decorator


def _raise_budget_exceeded(tool_name: str, session_id: str, count: int):
    resp = json.dumps({
        "status": "blocked", "decision": "BLOCK",
        "reason": f"Session block budget exhausted ({MAX_BLOCKS_PER_SESSION} blocked calls).",
        "hint": "This session has triggered too many security blocks.",
        "retry_allowed": False, "action_taken": "session_halted",
    })
    raise ZerofalseSecurity(
        tool_name=tool_name, risk_score=1.0,
        threat_type="session_budget_exceeded",
        evidence=[f"Session {session_id!r} blocked {count} times"],
        scan_id="budget-exceeded", structured_response=resp,
    )
