"""LangChain integration — sync and async tool wrapper."""
import json
import logging
from typing import Any, Optional

try:
    from langchain.tools import BaseTool
except ImportError as e:
    raise ImportError("Install with: pip install zerofalse[langchain]") from e

logger = logging.getLogger("zerofalse")


class ZerofalseGuardedTool(BaseTool):
    """Wraps a LangChain BaseTool with Zerofalse enforcement."""
    wrapped_tool: Any
    zf_client: Optional[Any] = None
    zf_async_client: Optional[Any] = None
    agent_id: str = "langchain-agent"
    session_id: str = "default"

    class Config:
        arbitrary_types_allowed = True

    @classmethod
    def from_tool(
        cls, tool: BaseTool,
        agent_id: str = "langchain-agent",
        session_id: str = "default",
        api_key: Optional[str] = None,
        fail_open: bool = True,
    ) -> "ZerofalseGuardedTool":
        from ..client import AsyncZerofalseClient, ZerofalseClient
        return cls(
            name=tool.name, description=tool.description,
            wrapped_tool=tool,
            zf_client=ZerofalseClient(api_key=api_key, fail_open=fail_open),
            zf_async_client=AsyncZerofalseClient(api_key=api_key, fail_open=fail_open),
            agent_id=agent_id, session_id=session_id,
        )

    def _run(self, tool_input: str, **kwargs) -> str:
        from ..client import ZerofalseClient
        c = self.zf_client or ZerofalseClient()
        result = c.scan_tool_call(
            tool_name=self.name, arguments={"input": tool_input},
            agent_id=self.agent_id, session_id=self.session_id,
        )
        if result.is_blocked:
            return json.dumps({
                "zerofalse_block": True, "threat_type": result.threat_type,
                "reason": result.description, "hint": result.hint,
                "safe_alternatives": result.safe_alternatives,
                "retry_allowed": result.retry_allowed,
            })
        if result.is_warned:
            logger.warning("[WARN] tool=%s risk=%.0f%%", self.name, result.risk_score * 100)
        return self.wrapped_tool._run(tool_input, **kwargs)

    async def _arun(self, tool_input: str, **kwargs) -> str:
        from ..client import AsyncZerofalseClient
        c = self.zf_async_client or AsyncZerofalseClient()
        result = await c.scan_tool_call(
            tool_name=self.name, arguments={"input": tool_input},
            agent_id=self.agent_id, session_id=self.session_id,
        )
        if result.is_blocked:
            return json.dumps({
                "zerofalse_block": True, "threat_type": result.threat_type,
                "reason": result.description, "hint": result.hint,
                "safe_alternatives": result.safe_alternatives,
                "retry_allowed": result.retry_allowed,
            })
        if result.is_warned:
            logger.warning("[WARN] tool=%s risk=%.0f%%", self.name, result.risk_score * 100)
        return await self.wrapped_tool._arun(tool_input, **kwargs)
