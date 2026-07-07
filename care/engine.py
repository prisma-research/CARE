"""CARE engine: Canonicalization + Attribution orchestrator.

Implements Stage 1 (Canonicalization) and Stage 2 (Attribution, layers
L1-L5) of the CARE pipeline (Algorithm 1, Sec. III). Stage 3 (Resolution)
is a separate, optional module (`care.resolution`) because it may call an
external LLM judge; the engine here is fully deterministic and never issues
a network call.

Public API:
    CAREEngine.analyze(cmd)      -> AnalysisResult (full evidence trace)
    CAREEngine.is_dangerous(cmd) -> bool           (WARN or DENY)
    CAREEngine.warn_trace(cmd)   -> (is_warn, trace_dict)  (for Resolution)

Mapping to the paper:
    Stage 1 Canonicalization  ->  care.canonicalization.normalize   (operator N)
    Stage 2 L1 Structure      ->  care.structure.ASTParser          (Eq. 1, delta_struct)
    Stage 2 L2 Semantic       ->  care.semantic.SemanticClassifier  (Eq. 2, s_sem)
    Stage 2 L3 Path           ->  care.path.PathValidator           (Eq. 3-4, s_path)
    Stage 2 L4 Pattern        ->  care.pattern.PatternDetector      (Eq. 5, s_pat)
    Stage 2 L5 Policy         ->  care.policy (compose/decide)      (Eq. 6-7, score, d_prov)

Fail-closed behaviour (Algorithm 1): when bashlex cannot parse the
canonicalized command, L1 falls back to a regex scan (see
care.structure.ASTParser._fallback) that still detects strong high-risk
tokens (e.g. `| bash`, `eval`); the surviving evidence propagates through
L2-L5, so an un-parseable but dangerous command is still denied rather than
silently allowed.
"""
import time

from .common import RiskLevel, RiskClass, AnalysisResult, CLASS_BASE_SCORE
from .structure import ASTParser
from .semantic import SemanticClassifier
from .path import PathValidator
from .pattern import PatternDetector
from .policy import PolicyConfig, compose, decide
from .modes import OperatingMode, policy_for
from .canonicalization import normalize as canonicalize


class CAREEngine:
    """Deterministic Canonicalization + Attribution engine (Stages 1-2).

    Default weights and thresholds reproduce the paper's balanced operating
    point (w_sem=w_path=w_pat=0.30, w_struct=0.10; tau_low=0.15,
    tau_high=0.35). Supplying `mode` overrides only the (tau_low, tau_high)
    thresholds via a named preset (strict/balanced/auto); `disable_layers`
    is provided for the layer-ablation study.
    """

    def __init__(self, workspace: str = ".",
                 w_sem: float = 0.30, w_path: float = 0.30,
                 w_pat: float = 0.30, w_struct: float = 0.10,
                 threshold_low: float = 0.15, threshold_high: float = 0.35,
                 disable_layers: tuple = (),
                 mode: "OperatingMode | str | None" = None):
        self.ast_parser       = ASTParser()
        self.semantic         = SemanticClassifier()
        self.path_validator   = PathValidator(workspace)
        self.pattern_detector = PatternDetector()
        # If a mode is supplied, its (tau_low, tau_high) preset overrides the
        # explicit threshold args. Mode is purely a configuration layer.
        if mode is not None:
            base = PolicyConfig(
                w_sem=w_sem, w_path=w_path, w_pat=w_pat, w_struct=w_struct,
                threshold_low=threshold_low, threshold_high=threshold_high,
            )
            self.cfg = policy_for(mode, base=base)
            self.mode = OperatingMode(mode) if not isinstance(mode, OperatingMode) else mode
        else:
            self.cfg = PolicyConfig(
                w_sem=w_sem, w_path=w_path, w_pat=w_pat, w_struct=w_struct,
                threshold_low=threshold_low, threshold_high=threshold_high,
            )
            self.mode = None
        # `disable_layers` — set of layer names to zero out for layer ablation
        #   'ast' | 'semantic' | 'path' | 'pattern' | 'provenance' | 'struct'
        self.disabled = set(disable_layers)

    # ---------- public API ----------

    def analyze(self, cmd: str) -> AnalysisResult:
        start = time.perf_counter()
        triggered = []
        details = {}
        fired_rules = []

        # Stage 1 — Canonicalization (operator N).
        # Expand IFS / variable-splitting / $(echo X) / base64 / printf-hex and
        # unwrap outer shell wrappers so downstream L1-L4 analysis sees the
        # deobfuscated verification target. The operator is append-augmenting
        # (keeps the original tokens), so no information is lost.
        raw_cmd = cmd
        cmd = canonicalize(cmd)

        # L1 Structure (Eq. 1)
        if 'ast' in self.disabled:
            ast_out = {'atoms': [cmd], 'structure_risk': 0.0,
                       'has_pipe': False, 'has_pipe_to_exec': False,
                       'has_command_sub': False, 'has_eval': False,
                       'parse_error': False}
        else:
            ast_out = self.ast_parser.parse(cmd)
        details['ast'] = {
            'atoms': len(ast_out['atoms']),
            'has_pipe': ast_out['has_pipe'],
            'has_pipe_to_exec': ast_out['has_pipe_to_exec'],
            'has_command_sub': ast_out['has_command_sub'],
            'has_eval': ast_out['has_eval'],
            'structure_risk': ast_out['structure_risk'],
        }
        if ast_out['structure_risk'] > 0:
            triggered.append('L1_AST')
        struct_score = 0.0 if 'struct' in self.disabled else ast_out['structure_risk']

        # L2 Semantic (Eq. 2) — per atom, take max
        if 'semantic' in self.disabled:
            sem_score = 0.0
            details['semantic'] = []
        else:
            best = 0.0
            best_cls = RiskClass.READ_ONLY
            sem_details = []
            for atom in (ast_out['atoms'] or [cmd]):
                cls, s, reason = self.semantic.classify(atom)
                sem_details.append({
                    'atom': atom[:120], 'class': cls.value, 'score': s, 'reason': reason,
                })
                if s > best:
                    best, best_cls = s, cls
            sem_score = best
            details['semantic'] = sem_details
            details['semantic_max_class'] = best_cls.value
            if sem_score > 0:
                triggered.append('L2_Semantic')

        # L3 Path (Eq. 3-4)
        if 'path' in self.disabled:
            path_score = 0.0
            details['path'] = {'score': 0.0, 'reason': 'disabled', 'triggered': []}
        else:
            path_score, path_reason, path_triggered = self.path_validator.validate(cmd)
            details['path'] = {'score': path_score, 'reason': path_reason,
                               'triggered': path_triggered}
            if path_score > 0:
                triggered.append('L3_Path')

        # L4 Pattern (Eq. 5)
        if 'pattern' in self.disabled:
            pat_score = 0.0
            details['pattern'] = {'score': 0.0, 'matches': []}
        else:
            pat_score, pat_matches = self.pattern_detector.detect(cmd)
            # Provenance weighting can be ablated separately
            if 'provenance' in self.disabled:
                # Use raw confidence instead of provenance-weighted effective_score
                pat_score = max((m['confidence'] for m in pat_matches), default=0.0)
            details['pattern'] = {
                'score': pat_score,
                'matches': [m['rule_id'] for m in pat_matches],
            }
            fired_rules = pat_matches
            if pat_score > 0:
                triggered.append('L4_Pattern')

        # L5 Policy (Eq. 6-7): weighted aggregation + provisional triage
        final_score = compose(sem_score, path_score, pat_score, struct_score, self.cfg)
        decision = decide(final_score, self.cfg)

        if decision == 'ALLOW':
            risk = RiskLevel.SAFE
        elif decision == 'WARN':
            risk = RiskLevel.CAUTIOUS
        else:
            risk = RiskLevel.CRITICAL if final_score >= 0.85 else RiskLevel.RISKY

        details['scoring'] = {
            'sem_score':  round(sem_score,  4),
            'path_score': round(path_score, 4),
            'pat_score':  round(pat_score,  4),
            'struct_score': round(struct_score, 4),
            'final_score': round(final_score, 4),
            'weights': {
                'w_sem': self.cfg.w_sem, 'w_path': self.cfg.w_path,
                'w_pat': self.cfg.w_pat, 'w_struct': self.cfg.w_struct,
            },
            'thresholds': {
                'tau_low': self.cfg.threshold_low, 'tau_high': self.cfg.threshold_high,
            },
        }

        latency_ms = (time.perf_counter() - start) * 1000

        # Record the RAW (pre-canonicalization) command in the trace.
        # The canonicalized form is kept in details for debugging but must
        # never be mistaken for what the agent actually attempted to execute.
        if cmd != raw_cmd:
            details['normalized_command'] = cmd

        return AnalysisResult(
            command=raw_cmd,
            decision=decision,
            risk_level=risk,
            score=round(final_score, 4),
            triggered_layers=triggered,
            details=details,
            latency_ms=round(latency_ms, 4),
            fired_rules=fired_rules,
        )

    def is_dangerous(self, cmd: str) -> bool:
        return self.analyze(cmd).decision in ('WARN', 'DENY')

    def warn_trace(self, cmd: str) -> "tuple[bool, dict]":
        """Return (is_warn, trace) for Stage-3 Resolution escalation."""
        r = self.analyze(cmd)
        return (r.decision == 'WARN'), {
            'command': cmd,
            'score': r.score,
            'triggered_layers': r.triggered_layers,
            'fired_rules': [m['rule_id'] for m in r.fired_rules],
            'details': r.details,
        }
