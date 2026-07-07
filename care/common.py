"""Shared types for the CARE attribution layers."""
from dataclasses import dataclass, field
from enum import IntEnum, Enum


class RiskLevel(IntEnum):
    SAFE = 0
    CAUTIOUS = 1
    RISKY = 2
    CRITICAL = 3


class RiskClass(str, Enum):
    """L2 semantic risk classes (9 types, per final_Proposal §5.2)."""
    READ_ONLY              = "READ_ONLY"
    WRITE_LOCAL            = "WRITE_LOCAL"
    WRITE_SENSITIVE        = "WRITE_SENSITIVE"
    NETWORK_FETCH          = "NETWORK_FETCH"
    EXECUTION_CHAIN        = "EXECUTION_CHAIN"
    PRIVILEGE_OR_PERMISSION = "PRIVILEGE_OR_PERMISSION"
    PERSISTENCE            = "PERSISTENCE"
    DESTRUCTIVE            = "DESTRUCTIVE"
    RESOURCE_ABUSE         = "RESOURCE_ABUSE"
    UNKNOWN                = "UNKNOWN"


# Base risk score for each class (∈ [0, 1]). Boost logic in semantic.py.
CLASS_BASE_SCORE = {
    RiskClass.READ_ONLY:               0.00,
    RiskClass.WRITE_LOCAL:             0.15,
    RiskClass.WRITE_SENSITIVE:         0.70,
    RiskClass.NETWORK_FETCH:           0.40,
    RiskClass.EXECUTION_CHAIN:         0.60,
    RiskClass.PRIVILEGE_OR_PERMISSION: 0.75,
    RiskClass.PERSISTENCE:             0.80,
    RiskClass.DESTRUCTIVE:             1.00,
    RiskClass.RESOURCE_ABUSE:          0.85,
    RiskClass.UNKNOWN:                 0.35,
}


@dataclass
class AnalysisResult:
    command: str
    decision: str                      # ALLOW, WARN, DENY
    risk_level: RiskLevel
    score: float
    triggered_layers: list = field(default_factory=list)
    details: dict          = field(default_factory=dict)
    latency_ms: float      = 0.0
    # populated by pattern.py: list of fired rule IDs with provenance
    fired_rules: list      = field(default_factory=list)
