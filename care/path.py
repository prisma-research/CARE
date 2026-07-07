"""L3 — Path-sensitive validation (read-vs-write aware).

Key discrimination added 2026-04-17:
  - READ-context on non-secret sensitive paths (e.g. `find /`, `cat /etc/group`,
    `tail /var/log/app.log`) → low penalty only.
  - WRITE-context on sensitive paths (e.g. `echo X > /etc/passwd`,
    `chmod 777 /etc/*`) → high penalty as before.
  - Genuinely-secret paths (shadow, id_rsa, aws/credentials) → always high
    regardless of context, because the act of reading them IS the attack.
  - SYSTEM_ROOT_TARGETS only hard-fail when the command head is a destructive
    or write operation; read-only walks of `/` (`find /`, `du -sh /`) are OK.
"""
import os
import re


# -------------- path catalogs --------------

# Critical: reading or writing these is always an attack indicator
CRITICAL_PATH_PATTERNS = [
    re.compile(r'^/dev/(sd|hd|nvme|vd|md|mmcblk|loop)'),  # block devices
    re.compile(r'/etc/(shadow|gshadow|sudoers)(\s|$|/)'),   # passwd excluded (world-readable)
    re.compile(r'\.ssh/authorized_keys'),
    re.compile(r'\.ssh/id_(rsa|ed25519|ecdsa|dsa)\b'),
    # Kernel control surfaces — writes here can panic, leak, or remap memory
    re.compile(r'/proc/(sysrq-trigger|kallsyms|kcore|kmsg|self/mem|kmem)\b'),
    re.compile(r'/sys/kernel/(kexec|debug|tracing|security)\b'),
]

# Secret-bearing paths — reading them IS the attack (credentials, keys, auth)
SECRET_READ_PATHS = (
    '~/.ssh/id_', '~/.ssh/authorized_keys',
    '~/.aws/credentials', '~/.docker/config.json',
    '~/.kube/config', '~/.gnupg/', '~/.netrc',
    '~/.mysql_history',
    '/etc/shadow', '/etc/gshadow', '/etc/sudoers',
    '/root/.ssh',
)

# Sensitive system paths — WRITE is dangerous, READ mostly benign
SENSITIVE_WRITE_PATHS = (
    '/etc/', '/boot/', '/sys/', '/proc/sys/', '/root/',
    '/var/log/', '/var/lib/',
    '/dev/',          # writing to any /dev/ is suspicious
)

# Benign device pseudo-files — writes here are universally safe (discard,
# process streams, pty). Critical block-device targets (/dev/sd*, /dev/nvme*,
# etc.) are already covered by CRITICAL_PATH_PATTERNS and pattern rules
# SE-P-005..SE-P-009 at higher confidence.
BENIGN_DEVICE_PATHS = (
    '/dev/null', '/dev/zero', '/dev/random', '/dev/urandom',
    '/dev/stdout', '/dev/stderr', '/dev/stdin',
    '/dev/tty', '/dev/pts/', '/dev/fd/',
)

# System-root sinks — critical only for destructive write operations
SYSTEM_ROOT_TARGETS = {'/', '/*', '/home', '/etc', '/usr', '/var',
                      '/opt', '/srv', '/boot', '/bin', '/sbin', '/lib', '/lib64'}

# Commands whose role is primarily READ/SEARCH/INSPECT (benign on sensitive paths)
READ_ONLY_HEADS = {
    'cat', 'head', 'tail', 'less', 'more', 'wc', 'nl', 'od', 'xxd',
    'hexdump', 'strings',
    'grep', 'egrep', 'fgrep', 'rg', 'ag', 'ack',
    'find', 'locate', 'which', 'whereis', 'type',
    'ls', 'll', 'dir', 'tree', 'file', 'stat', 'readlink', 'realpath',
    'du', 'df', 'stat',
    'awk', 'sed',            # sed without -i stays read
    'cut', 'sort', 'uniq', 'tr', 'column', 'paste', 'diff', 'cmp',
    'jq', 'yq',
    'echo', 'printf',
    'ps', 'top', 'htop', 'free', 'uptime', 'date',
    'uname', 'id', 'whoami', 'hostname', 'env', 'printenv',
    'md5sum', 'sha1sum', 'sha256sum',
    'mount',                 # mount without flags that would remount
    'rsync',                 # local rsync is write-local but flagged separately
}

# Commands whose role is WRITE/MODIFY
WRITE_HEADS = {
    'cp', 'mv', 'mkdir', 'touch', 'ln', 'rm', 'rmdir',
    'dd', 'mkfs', 'shred', 'wipefs', 'fdisk', 'truncate', 'fallocate',
    'chmod', 'chown', 'chgrp', 'setcap',
    'tar', 'zip', 'unzip', 'gzip', 'gunzip',  # can extract
    'apt', 'apt-get', 'yum', 'dnf', 'pacman', 'npm', 'pip', 'pip3',
    'make', 'gcc', 'g++', 'cmake',
    'git',
}


# -------------- helpers --------------

def _head(cmd: str) -> str:
    # If the command has been unwrapped by the L0 normalizer and carries a
    # <SHELL_C>INNER</SHELL_C> marker, the real head is INNER's head, not the
    # wrapper (bash/sh/busybox). Prefer the inner head when present.
    m = re.search(r'<SHELL_C>\s*(\S+)', cmd)
    if m:
        return os.path.basename(m.group(1))
    tokens = cmd.strip().split()
    if not tokens:
        return ''
    return os.path.basename(tokens[0])


def _has_write_context(cmd: str) -> bool:
    """Return True if the command performs a write/modify operation
    (write-head / redirection / append / pipe-to-write-head / sudo+write)."""
    head = _head(cmd)
    if head in WRITE_HEADS:
        return True
    if head == 'sudo':
        # sudo + write head → write context
        toks = cmd.split()
        if len(toks) > 1 and os.path.basename(toks[1]) in WRITE_HEADS:
            return True
    # redirection targets (`>`, `>>`) indicate write
    if re.search(r'(?<![0-9&])>{1,2}\s*\S', cmd):
        return True
    # sed -i is in-place write
    if head == 'sed' and re.search(r'\bsed\s+[^|;]*-i\b', cmd):
        return True
    # tee without `-a` still writes
    if re.search(r'\btee\b\s+(-a\s+)?\S', cmd):
        return True
    return False


def _is_destructive_head(cmd: str) -> bool:
    head = _head(cmd)
    destructive = {'rm', 'dd', 'mkfs', 'shred', 'wipefs', 'fdisk', 'parted',
                   'gdisk', 'sgdisk', 'cfdisk', 'truncate'}
    if head in destructive:
        return True
    if head == 'sudo':
        toks = cmd.split()
        return len(toks) > 1 and os.path.basename(toks[1]) in destructive
    # redirection that overwrites a file with raw output
    if re.search(r'>\s*/dev/(sd|hd|nvme|vd)', cmd):
        return True
    return False


# -------------- main validator --------------

class PathValidator:
    def __init__(self, workspace: str = "."):
        self.workspace = os.path.abspath(workspace)

    def validate(self, cmd: str) -> tuple[float, str, list]:
        paths = self._extract_paths(cmd)
        if not paths:
            return 0.0, "paths_ok", []

        head = _head(cmd)
        is_read = head in READ_ONLY_HEADS
        writing = _has_write_context(cmd)
        destructive = _is_destructive_head(cmd)

        # Explicit per-path write targets: redirect targets, sed -i file arg,
        # tee arg. A read-only head like `echo` or `awk` followed by `>`
        # still writes to the redirect target, so we must not let the head
        # heuristic override a concrete write target.
        write_targets = set()
        for m in re.finditer(r'>{1,2}\s*([^\s;&|]+)', cmd):
            t = m.group(1).strip('"\'')
            write_targets.add(t); write_targets.add(os.path.expanduser(t))
        if re.search(r'\bsed\s+[^|;]*-i\b', cmd):
            sed_seg = re.search(r'\bsed\s+[^|;]+', cmd)
            if sed_seg:
                for tok in sed_seg.group(0).split():
                    t = tok.strip('"\'')
                    if t.startswith(('/', '~')):
                        write_targets.add(t); write_targets.add(os.path.expanduser(t))
        for m in re.finditer(r'\btee\b\s+(?:-a\s+)?([^\s|&;]+)', cmd):
            t = m.group(1).strip('"\'')
            if t.startswith(('/', '~', './')):
                write_targets.add(t); write_targets.add(os.path.expanduser(t))

        triggered = []
        max_score = 0.0
        reason = "paths_ok"

        for p in paths:
            expanded = os.path.expanduser(p)
            # Does this specific path receive a write?
            is_write_this = (p in write_targets) or (expanded in write_targets)

            # (a) System-root sink → hard-fail ONLY for destructive heads
            if (p in SYSTEM_ROOT_TARGETS or expanded in SYSTEM_ROOT_TARGETS):
                if destructive:
                    triggered.append(p)
                    return 1.0, f"destructive_on_system_root:{p}", triggered
                # otherwise benign (e.g. `find /`, `du -sh /`) — no penalty

            # (b) Critical patterns — device writes, secret files, authorized_keys
            for pat in CRITICAL_PATH_PATTERNS:
                if pat.search(expanded) or pat.search(p):
                    # Block-device write is critical; block-device READ (rare) still high
                    triggered.append(p)
                    return 1.0, f"critical_path:{p}", triggered

            # (c) Secret-bearing READ paths (shadow, id_rsa, creds) — always high
            for sp in SECRET_READ_PATHS:
                if (expanded.startswith(sp) or p.startswith(sp) or
                        sp.lstrip('~') in expanded):
                    score = 0.85
                    if score > max_score:
                        max_score = score
                        reason = f"secret_path:{p}"
                    if p not in triggered: triggered.append(p)

            # (d) Sensitive SYSTEM paths: penalty depends on read vs write context
            # Short-circuit benign /dev/ pseudo-files (null/zero/stdout/tty/pts).
            if any(expanded.startswith(b) or p.startswith(b) for b in BENIGN_DEVICE_PATHS):
                continue
            for sp in SENSITIVE_WRITE_PATHS:
                if expanded.startswith(sp) or p.startswith(sp):
                    # A concrete write target (redirect, sed -i, tee) overrides
                    # a read-only head. `echo X > /etc/profile` writes to /etc/
                    # even though echo is in READ_ONLY_HEADS.
                    if is_write_this or (writing and not is_read):
                        score = 0.70
                        why = f"sensitive_write:{p}"
                    elif is_read and not writing:
                        score = 0.10          # tiny penalty: legitimate diagnostic reads
                        why = f"sensitive_read:{p}"
                    else:
                        score = 0.35          # ambiguous context
                        why = f"sensitive_ambiguous:{p}"
                    if score > max_score:
                        max_score = score
                        reason = why
                    if p not in triggered: triggered.append(p)

            # (e) Path traversal (independent of head)
            if '../' in p:
                score = 0.3 if is_read else 0.5
                if score > max_score:
                    max_score = score
                    reason = f"path_traversal:{p}"
                if p not in triggered: triggered.append(p)

        return max_score, reason, triggered

    # --------- token extraction ---------
    def _extract_paths(self, cmd: str) -> list:
        paths = []
        # Strip L0 normalizer markup so tokens don't include closing tags.
        cmd = re.sub(r'\x1f?<(?:B64DEC|HEXDEC|OCTDEC|PY_B64|SHELL_C)>', ' ', cmd)
        cmd = re.sub(r'</(?:B64DEC|HEXDEC|OCTDEC|PY_B64|SHELL_C)>\x1f?', ' ', cmd)
        tokens = re.findall(r'"[^"]+"|\'[^\']+\'|\S+', cmd)
        for tok in tokens:
            t = tok.strip('"\'')
            if not t:
                continue
            if t.startswith('-') and not t.startswith('/'):
                if '=' in t:
                    rhs = t.split('=', 1)[1]
                    if rhs.startswith(('/', '~', './')) or '../' in rhs:
                        paths.append(rhs)
                continue
            if t.startswith(('/', '~', './')) or '../' in t:
                paths.append(t)
        for m in re.finditer(r'>{1,2}\s*([^\s;&|]+)', cmd):
            tgt = m.group(1).strip('"\'')
            if tgt and (tgt.startswith(('/', '~', './')) or '../' in tgt):
                paths.append(tgt)
        return paths
