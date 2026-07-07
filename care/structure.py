"""L1 — AST parsing via bashlex, with string-level fallback.

Produces a structural summary of the candidate command:
  atoms, has_pipe, has_redirect, has_command_sub, has_eval,
  has_pipe_to_exec, parse_error, structure_risk ∈ [0, 1]
"""
import re

try:
    import bashlex
    HAS_BASHLEX = True
except ImportError:
    HAS_BASHLEX = False


_EXEC_INTERPRETERS = {'bash', 'sh', 'zsh', 'dash', 'ksh', 'csh', 'tcsh',
                      'eval', 'python', 'python2', 'python3', 'perl', 'ruby',
                      'node', 'lua', 'php'}


class ASTParser:
    def parse(self, cmd: str) -> dict:
        result = {
            'atoms': [],
            'has_pipe': False,
            'has_redirect': False,
            'has_command_sub': False,
            'has_eval': False,
            'has_pipe_to_exec': False,
            'parse_error': False,
            'nested_sub_depth': 0,
            'structure_risk': 0.0,
        }
        if not HAS_BASHLEX:
            return self._fallback(cmd, result)
        try:
            parts = bashlex.parse(cmd)
            self._visit(parts, result, depth=0)
        except Exception:
            result['parse_error'] = True
            return self._fallback(cmd, result)
        self._score(result)
        return result

    def _visit(self, nodes, result, depth):
        if not isinstance(nodes, list):
            nodes = [nodes]
        for node in nodes:
            if not hasattr(node, 'kind'):
                continue
            kind = node.kind

            if kind == 'command':
                words = [p.word for p in getattr(node, 'parts', [])
                         if hasattr(p, 'word')]
                if words:
                    result['atoms'].append(' '.join(words))
                    if words[0] in ('eval', 'source', '.'):
                        result['has_eval'] = True

            elif kind == 'pipeline':
                result['has_pipe'] = True
                pipe_parts = getattr(node, 'parts', [])
                if len(pipe_parts) >= 2:
                    last = pipe_parts[-1]
                    name = self._head_name(last)
                    if name in _EXEC_INTERPRETERS:
                        result['has_pipe_to_exec'] = True
                self._visit(pipe_parts, result, depth)

            elif kind == 'compound':
                for child in getattr(node, 'list', []):
                    self._visit([child], result, depth)

            elif kind == 'commandsubstitution':
                result['has_command_sub'] = True
                result['nested_sub_depth'] = max(result['nested_sub_depth'], depth + 1)
                if hasattr(node, 'command'):
                    self._visit([node.command], result, depth + 1)

            elif kind in ('redirect', 'heredoc'):
                result['has_redirect'] = True

            elif kind == 'list':
                for part in getattr(node, 'parts', []):
                    self._visit([part], result, depth)

            # Recurse generically into remaining list-valued attrs
            for attr in ('list',):
                child = getattr(node, attr, None)
                if child and isinstance(child, list):
                    self._visit(child, result, depth)

    def _head_name(self, node) -> str:
        if hasattr(node, 'parts'):
            for p in node.parts:
                if hasattr(p, 'word'):
                    return p.word
        return ''

    def _score(self, result):
        # Pipe-to-interpreter (curl | bash, echo | sh) is a strong indicator.
        if result['has_pipe_to_exec']:
            result['structure_risk'] = 1.0
        # Explicit eval / source of untrusted content.
        elif result['has_eval']:
            result['structure_risk'] = 0.9
        # Nested substitution (3+ deep) is rarely benign.
        elif result['nested_sub_depth'] >= 2:
            result['structure_risk'] = 0.6
        # Plain single-level $() or backticks are common in benign scripting
        # (`$(uname -s)`, `$(date)`) but are also the main obfuscation vector
        # (substitution_nesting, variable_splitting). Mid penalty balances
        # both; L4 patterns handle obvious abuse explicitly.
        elif result['has_command_sub']:
            result['structure_risk'] = 0.30
        # Plain pipe with non-interpreter target (e.g. `ps | grep`) is benign.
        elif result['has_pipe']:
            result['structure_risk'] = 0.05

    def _fallback(self, cmd: str, result: dict) -> dict:
        result['atoms'] = [cmd]
        result['has_pipe'] = '|' in cmd
        result['has_redirect'] = '>' in cmd
        result['has_command_sub'] = '$(' in cmd or '`' in cmd
        result['has_eval'] = bool(re.search(r'\b(eval|source)\b', cmd))
        result['has_pipe_to_exec'] = bool(
            re.search(r'\|\s*(bash|sh|zsh|dash|eval|python[23]?|perl|ruby|node)\b', cmd))
        result['nested_sub_depth'] = cmd.count('$(') + cmd.count('`') // 2
        self._score(result)
        return result
