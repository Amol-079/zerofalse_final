"""SDK exceptions."""
from typing import List, Optional


class ZerofalseSecurity(Exception):
    """Raised when Zerofalse BLOCKS a tool call. The tool never executes.
    
    structured_response: JSON string with hint + safe_alternatives for agent observation.
    """
    def __init__(
        self,
        tool_name: str,
        risk_score: float,
        threat_type: str,
        evidence: List[str],
        scan_id: str,
        structured_response: Optional[str] = None,
    ):
        self.tool_name = tool_name
        self.risk_score = risk_score
        self.threat_type = threat_type
        self.evidence = evidence
        self.scan_id = scan_id
        self.structured_response = structured_response
        super().__init__(
            structured_response or (
                f"[ZEROFALSE BLOCKED] tool={tool_name} "
                f"risk={risk_score:.0%} threat={threat_type} scan_id={scan_id}"
            )
        )


class ZerofalseWarning(UserWarning):
    """Issued for WARN decisions. Tool executes but caller is warned."""
    pass


class ZerofalseNetworkError(Exception):
    """Raised when fail_open=False and API is unreachable."""
    pass
