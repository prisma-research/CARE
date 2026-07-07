"""L5 — Provenance-aware weighted policy.

Composite risk score:
    score(c) = w_sem·s_sem + w_path·s_path + w_pat·s_pat + w_struct·δ_struct
Decision:
    ALLOW if score < τ_low
    WARN  if τ_low ≤ score < τ_high
    DENY  if score ≥ τ_high
"""
from dataclasses import dataclass


@dataclass
class PolicyConfig:
    w_sem:    float = 0.30
    w_path:   float = 0.30
    w_pat:    float = 0.30
    w_struct: float = 0.10
    threshold_low:  float = 0.15   # tuned on dev split; raises DR from 37→72% at modest FPR cost
    threshold_high: float = 0.35   # opens a narrow WARN band for LLM escalation


def compose(sem_score: float, path_score: float, pat_score: float,
            struct_score: float, cfg: PolicyConfig) -> float:
    return (cfg.w_sem    * sem_score  +
            cfg.w_path   * path_score +
            cfg.w_pat    * pat_score  +
            cfg.w_struct * struct_score)


def decide(score: float, cfg: PolicyConfig) -> str:
    if score < cfg.threshold_low:
        return 'ALLOW'
    if score < cfg.threshold_high:
        return 'WARN'
    return 'DENY'
