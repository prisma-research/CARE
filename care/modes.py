"""Operating modes for CARE -- deployment-context aware policy presets.

Three modes:
  - balanced  (default; matches the values used to produce the frozen results)
  - strict    (tighter thresholds — favor low FPR over recall, e.g. CI gate)
  - auto      (wider WARN band — favor recall, lean on LLM escalation)

The mode is purely a configuration layer over the existing PolicyConfig:
no behavior change for the default `balanced` mode.
"""
from dataclasses import dataclass
from enum import Enum

from .policy import PolicyConfig


class OperatingMode(str, Enum):
    BALANCED = "balanced"
    STRICT   = "strict"
    AUTO     = "auto"


@dataclass(frozen=True)
class ModePreset:
    mode: OperatingMode
    threshold_low:  float
    threshold_high: float
    description:    str


# Tuned empirically on the dev split. balanced reproduces frozen-D3 defaults.
MODE_PRESETS = {
    OperatingMode.BALANCED: ModePreset(
        mode=OperatingMode.BALANCED,
        threshold_low=0.15, threshold_high=0.35,
        description="Default. Matches the values used for the main results.",
    ),
    OperatingMode.STRICT: ModePreset(
        mode=OperatingMode.STRICT,
        threshold_low=0.10, threshold_high=0.20,
        description=(
            "Conservative: more decisions land in WARN/DENY. Suitable when "
            "false positives are tolerable (e.g. CI pre-merge gate)."
        ),
    ),
    OperatingMode.AUTO: ModePreset(
        mode=OperatingMode.AUTO,
        threshold_low=0.20, threshold_high=0.50,
        description=(
            "Wider WARN band, fewer hard denials. Designed to delegate "
            "borderline cases to an LLM judge while keeping clear-cut "
            "ALLOW/DENY decisions deterministic."
        ),
    ),
}


def policy_for(mode: OperatingMode | str,
               base: PolicyConfig | None = None) -> PolicyConfig:
    """Return a PolicyConfig populated from the requested mode.

    Other PolicyConfig fields (weights) are kept from `base` if supplied.
    """
    m = OperatingMode(mode) if not isinstance(mode, OperatingMode) else mode
    p = MODE_PRESETS[m]
    if base is None:
        return PolicyConfig(
            threshold_low=p.threshold_low,
            threshold_high=p.threshold_high,
        )
    return PolicyConfig(
        w_sem=base.w_sem, w_path=base.w_path,
        w_pat=base.w_pat, w_struct=base.w_struct,
        threshold_low=p.threshold_low,
        threshold_high=p.threshold_high,
    )
