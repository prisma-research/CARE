"""CARE: Canonicalization, Attribution, and Resolution Engine.

A shell-specific, static-first pre-execution verifier for shell-executing
LLM agents. CARE canonicalizes a candidate command, derives deterministic
multi-view evidence (syntax, command semantics, path context, provenance-
backed risk patterns), and escalates only borderline WARN-band commands to
an LLM judge.

Typical use
-----------
Static-only engine (deterministic, no network call)::

    from care import CAREEngine
    eng = CAREEngine()
    r = eng.analyze("rm -rf /var/log/*")
    print(r.decision, r.score)          # 'DENY' 0.765

Full pipeline with Resolution (adds an LLM judge on WARN)::

    from care import CARE
    guard = CARE()                      # use_judge=True by default
    print(guard.is_dangerous("rsync -avz ./data user@host:/backup/"))

Static-only "CARE (w/o Resolution)" configuration::

    from care import CARE
    guard = CARE(use_judge=False)       # WARN and DENY both blocked
"""
from .common import RiskLevel, RiskClass, AnalysisResult, CLASS_BASE_SCORE
from .engine import CAREEngine
from .modes import OperatingMode, policy_for
from .policy import PolicyConfig, compose, decide
from .resolution import CARE

__all__ = [
    "CAREEngine",
    "CARE",
    "OperatingMode",
    "policy_for",
    "PolicyConfig",
    "compose",
    "decide",
    "RiskLevel",
    "RiskClass",
    "AnalysisResult",
    "CLASS_BASE_SCORE",
]

__version__ = "1.0.0"
