"""SDK data models."""
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ScanResult:
    scan_id: str
    decision: str
    risk_score: float
    severity: str
    threat_type: Optional[str]
    title: str
    description: str
    evidence: List[str] = field(default_factory=list)
    latency_ms: float = 0.0
    timestamp: Optional[str] = None
    hint: Optional[str] = None
    safe_alternatives: List[str] = field(default_factory=list)
    retry_allowed: bool = True
    action_taken: str = "logged"
    pattern_id: Optional[str] = None

    @property
    def is_blocked(self) -> bool:
        return self.decision == "block"

    @property
    def is_warned(self) -> bool:
        return self.decision == "warn"

    @property
    def is_allowed(self) -> bool:
        return self.decision == "allow"
