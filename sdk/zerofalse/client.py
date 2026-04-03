"""
Zerofalse SDK Client v2.0

ZerofalseClient      — synchronous (scripts, Flask, background jobs)
AsyncZerofalseClient — async (FastAPI, LangChain async, asyncio agents)

Use AsyncZerofalseClient in any async context. The sync client blocks the
calling thread and must never be awaited or called from an event loop.
"""
import json
import logging
import os
from typing import Optional

import httpx

from .exceptions import ZerofalseNetworkError
from .models import ScanResult

logger = logging.getLogger("zerofalse")

_DEFAULT_API_URL = "https://api.zerofalse.com"


def _build_result(data: dict) -> ScanResult:
    return ScanResult(
        scan_id=data.get("scan_id", "unknown"),
        decision=data.get("decision", "allow"),
        risk_score=float(data.get("risk_score", 0.0)),
        severity=data.get("severity", "info"),
        threat_type=data.get("threat_type"),
        title=data.get("title", ""),
        description=data.get("description", ""),
        evidence=data.get("evidence", []),
        latency_ms=float(data.get("latency_ms", 0.0)),
        timestamp=data.get("timestamp"),
        hint=data.get("hint"),
        safe_alternatives=data.get("safe_alternatives", []),
        retry_allowed=data.get("retry_allowed", True),
        action_taken=data.get("action_taken", "logged"),
        pattern_id=data.get("pattern_id"),
    )


def _fail_open() -> ScanResult:
    return ScanResult(
        scan_id="fail-open", decision="allow", risk_score=0.0,
        severity="info", threat_type=None, title="Fail-open",
        description="Zerofalse unreachable — fail-open policy applied",
        evidence=[], latency_ms=0.0, action_taken="fail-open",
    )


class ZerofalseClient:
    """Synchronous client. Do NOT use in async contexts."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        api_url: Optional[str] = None,
        fail_open: bool = True,
        timeout: float = 5.0,
    ):
        self.api_key = api_key or os.environ.get("ZEROFALSE_API_KEY")
        if not self.api_key:
            raise ValueError("ZEROFALSE_API_KEY not set.")
        self.api_url = api_url or os.environ.get("ZEROFALSE_API_URL") or _DEFAULT_API_URL
        self.fail_open = fail_open
        self._http = httpx.Client(
            base_url=self.api_url,
            headers={"X-API-Key": self.api_key, "Content-Type": "application/json"},
            timeout=timeout,
        )

    def scan_tool_call(
        self, tool_name: str, arguments: dict,
        agent_id: str = "default",
        caller_agent_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> ScanResult:
        payload = {
            "tool_name": tool_name, "arguments": arguments,
            "agent_id": agent_id, "caller_agent_id": caller_agent_id,
            "session_id": session_id,
        }
        try:
            r = self._http.post("/api/v1/scan/tool-call", content=json.dumps(payload))
            r.raise_for_status()
            return _build_result(r.json())
        except Exception as e:
            logger.warning("scan_tool_call failed: %s", e)
            if not self.fail_open:
                raise ZerofalseNetworkError(str(e)) from e
            return _fail_open()

    def scan_prompt(
        self, text: str, agent_id: str = "default",
        session_id: Optional[str] = None,
    ) -> ScanResult:
        payload = {"text": text, "agent_id": agent_id, "session_id": session_id}
        try:
            r = self._http.post("/api/v1/scan/prompt", content=json.dumps(payload))
            r.raise_for_status()
            return _build_result(r.json())
        except Exception as e:
            logger.warning("scan_prompt failed: %s", e)
            if not self.fail_open:
                raise ZerofalseNetworkError(str(e)) from e
            return _fail_open()

    def close(self):
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class AsyncZerofalseClient:
    """Async client — use in FastAPI, LangChain async, asyncio agents."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        api_url: Optional[str] = None,
        fail_open: bool = True,
        timeout: float = 5.0,
    ):
        self.api_key = api_key or os.environ.get("ZEROFALSE_API_KEY")
        if not self.api_key:
            raise ValueError("ZEROFALSE_API_KEY not set.")
        self.api_url = api_url or os.environ.get("ZEROFALSE_API_URL") or _DEFAULT_API_URL
        self.fail_open = fail_open
        self._http = httpx.AsyncClient(
            base_url=self.api_url,
            headers={"X-API-Key": self.api_key, "Content-Type": "application/json"},
            timeout=timeout,
        )

    async def scan_tool_call(
        self, tool_name: str, arguments: dict,
        agent_id: str = "default",
        caller_agent_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> ScanResult:
        payload = {
            "tool_name": tool_name, "arguments": arguments,
            "agent_id": agent_id, "caller_agent_id": caller_agent_id,
            "session_id": session_id,
        }
        try:
            r = await self._http.post("/api/v1/scan/tool-call", content=json.dumps(payload))
            r.raise_for_status()
            return _build_result(r.json())
        except Exception as e:
            logger.warning("async scan_tool_call failed: %s", e)
            if not self.fail_open:
                raise ZerofalseNetworkError(str(e)) from e
            return _fail_open()

    async def scan_prompt(
        self, text: str, agent_id: str = "default",
        session_id: Optional[str] = None,
    ) -> ScanResult:
        payload = {"text": text, "agent_id": agent_id, "session_id": session_id}
        try:
            r = await self._http.post("/api/v1/scan/prompt", content=json.dumps(payload))
            r.raise_for_status()
            return _build_result(r.json())
        except Exception as e:
            logger.warning("async scan_prompt failed: %s", e)
            if not self.fail_open:
                raise ZerofalseNetworkError(str(e)) from e
            return _fail_open()

    async def close(self):
        await self._http.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        await self.close()
