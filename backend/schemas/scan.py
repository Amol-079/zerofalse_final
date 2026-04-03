"""Scan request/response schemas."""
import json
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator


class ToolCallScanRequest(BaseModel):
    tool_name: str = Field(..., min_length=1, max_length=256)
    arguments: Dict[str, Any] = Field(...)
    agent_id: str = Field(..., min_length=1, max_length=128)
    session_id: Optional[str] = Field(None, max_length=128)
    caller_agent_id: Optional[str] = Field(None, max_length=128)

    @field_validator("arguments")
    @classmethod
    def validate_arguments_size(cls, v):
        if len(json.dumps(v, default=str)) > 65_536:
            raise ValueError("arguments payload exceeds 64 KB")
        return v


class PromptScanRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=32_768)
    agent_id: str = Field(..., min_length=1, max_length=128)
    session_id: Optional[str] = Field(None, max_length=128)


class ScanResponse(BaseModel):
    scan_id: str
    decision: Literal["allow", "warn", "block"]
    risk_score: float
    severity: Literal["critical", "high", "medium", "low", "info"]
    threat_type: Optional[str]
    title: str
    description: str
    evidence: List[str]
    latency_ms: float
    timestamp: datetime
    hint: Optional[str] = None
    safe_alternatives: List[str] = []
    retry_allowed: bool = True
    action_taken: str = "logged"
    pattern_id: Optional[str] = None


class BatchScanRequest(BaseModel):
    scans: List[ToolCallScanRequest] = Field(..., min_length=1, max_length=10)
