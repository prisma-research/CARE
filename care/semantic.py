"""L2 — Semantic risk typing.

Map a command's head (and key flags) to one of 9 `RiskClass` values
(final_Proposal §5.2) and emit a normalized risk score ∈ [0, 1].

Design goals:
  - deterministic, auditable
  - covers ~250 common bash utilities
  - flag-conditional and path-conditional boosts (rm vs rm -rf /, chmod vs chmod 777)
"""
import os
import re
from .common import RiskClass, CLASS_BASE_SCORE


# Head-of-command lexicon: command name -> default RiskClass
COMMAND_CLASSES = {
    # READ_ONLY ---------------------------------------------------------
    **dict.fromkeys([
        'cat', 'head', 'tail', 'less', 'more', 'wc', 'nl', 'od', 'hexdump', 'xxd', 'strings',
        'grep', 'egrep', 'fgrep', 'rg', 'ag', 'ack',
        'find', 'locate', 'which', 'whereis', 'type', 'command',
        'ls', 'll', 'dir', 'tree', 'file', 'stat', 'readlink', 'realpath',
        'pwd', 'whoami', 'id', 'groups', 'w', 'who', 'last', 'tty',
        'uname', 'hostname', 'date', 'uptime', 'cal', 'lsb_release',
        'df', 'du', 'free', 'top', 'htop', 'atop', 'iotop',
        'env', 'printenv', 'echo', 'printf', 'yes',
        'diff', 'cmp', 'comm', 'sort', 'uniq', 'cut', 'tr', 'awk', 'sed',  # sed default read; -i boosts
        'jq', 'yq', 'xmllint', 'column', 'paste', 'join', 'tac', 'rev',
        'man', 'help', 'info', 'tldr', 'whatis',
        'md5sum', 'sha1sum', 'sha256sum', 'sha512sum', 'b2sum', 'cksum',
        'true', 'false', 'test', '[',
        'history',  # read-only unless -c
        'bc', 'dc', 'seq', 'expr', 'sleep',
        'ping', 'traceroute', 'mtr', 'host', 'dig', 'nslookup',  # query-only network
        'ps', 'pgrep', 'pidof', 'jobs', 'pstree',
    ], RiskClass.READ_ONLY),

    # WRITE_LOCAL (workspace-scoped, mostly benign) ---------------------
    **dict.fromkeys([
        'cp', 'mv', 'mkdir', 'touch', 'ln',
        'tar', 'zip', 'unzip', 'gzip', 'gunzip', 'bzip2', 'xz', '7z', 'zstd',
        'tee',
        'make', 'cmake', 'gradle', 'mvn', 'ant', 'ninja', 'bazel',
        'pip', 'pip3', 'npm', 'yarn', 'pnpm', 'cargo', 'go', 'poetry',
        'python', 'python3', 'node', 'ruby', 'perl', 'php', 'lua',
        'git',            # subcommand-dispatched below
        'docker', 'podman', 'docker-compose',
        'kubectl', 'helm',
        'export', 'alias', 'unalias',
        'pytest', 'tox', 'nose2', 'rspec', 'jest', 'mocha', 'vitest',
        'gcc', 'g++', 'clang', 'javac', 'rustc', 'tsc',
        'vi', 'vim', 'nvim', 'nano', 'emacs',
    ], RiskClass.WRITE_LOCAL),

    # NETWORK_FETCH -----------------------------------------------------
    **dict.fromkeys([
        'curl', 'wget', 'httpie', 'aria2c',
        'rsync', 'scp', 'sftp', 'ftp',
        'apt', 'apt-get', 'yum', 'dnf', 'pacman', 'brew', 'snap', 'flatpak',
    ], RiskClass.NETWORK_FETCH),

    # EXECUTION_CHAIN (running shells/interpreters directly or indirectly) ------
    **dict.fromkeys([
        'bash', 'sh', 'zsh', 'dash', 'ksh', 'csh', 'tcsh', 'ash',
        'exec', 'source', '.',
    ], RiskClass.EXECUTION_CHAIN),

    # PRIVILEGE_OR_PERMISSION ------------------------------------------
    **dict.fromkeys([
        'sudo', 'su', 'doas', 'pkexec',
        'chmod', 'chown', 'chgrp', 'setcap', 'getcap',
        'visudo', 'passwd', 'chpasswd',
        'useradd', 'userdel', 'usermod', 'groupadd', 'groupdel', 'groupmod',
        'newgrp', 'adduser', 'deluser',
    ], RiskClass.PRIVILEGE_OR_PERMISSION),

    # PERSISTENCE ------------------------------------------------------
    **dict.fromkeys([
        'crontab', 'at', 'batch', 'anacron',
        'systemctl', 'service', 'update-rc.d', 'chkconfig',
        'launchctl',
    ], RiskClass.PERSISTENCE),

    # DESTRUCTIVE ------------------------------------------------------
    **dict.fromkeys([
        'rm',        # may escalate to DESTRUCTIVE with -rf or sensitive path
        'rmdir',
        'dd',        # often destructive with of=/dev/*
        'mkfs', 'mkfs.ext4', 'mkfs.ext3', 'mkfs.xfs', 'mkfs.btrfs', 'mkfs.vfat',
        'fdisk', 'parted', 'gdisk', 'sgdisk', 'cfdisk',
        'shred', 'wipe', 'wipefs', 'blkdiscard',
        'truncate',
    ], RiskClass.DESTRUCTIVE),

    # RESOURCE_ABUSE ---------------------------------------------------
    **dict.fromkeys([
        'kill', 'killall', 'pkill',
        'shutdown', 'reboot', 'halt', 'poweroff', 'init', 'telinit',
        'stress', 'stress-ng', 'fallocate',
        'nmap', 'hping3', 'masscan',
    ], RiskClass.RESOURCE_ABUSE),

    # WRITE_SENSITIVE (placeholder; most are routed via path boost rather than command head)
    **dict.fromkeys([
        'nc', 'ncat', 'netcat', 'ssh',     # connection-forming net utilities
    ], RiskClass.NETWORK_FETCH),
}


# Git subcommand-level risk mapping (overrides the default WRITE_LOCAL for `git ...`)
GIT_SUBCOMMAND_CLASSES = {
    # read-only
    **dict.fromkeys([
        'status', 'log', 'diff', 'show', 'blame', 'branch', 'tag', 'remote',
        'stash', 'ls-files', 'describe', 'shortlog', 'reflog', 'config',
    ], RiskClass.READ_ONLY),
    # write-local
    **dict.fromkeys([
        'add', 'commit', 'checkout', 'switch', 'merge', 'rebase', 'cherry-pick',
        'am', 'apply', 'init', 'fetch', 'pull', 'clone', 'tag',
    ], RiskClass.WRITE_LOCAL),
    # push/reset handled via flag boost below
    'push':  RiskClass.WRITE_LOCAL,
    'reset': RiskClass.WRITE_LOCAL,
    'clean': RiskClass.WRITE_LOCAL,
}


class SemanticClassifier:
    """Return (RiskClass, score ∈ [0, 1], reason string)."""

    def classify(self, atom: str) -> tuple[RiskClass, float, str]:
        tokens = atom.strip().split()
        if not tokens:
            return RiskClass.READ_ONLY, 0.0, "empty"

        prog = os.path.basename(tokens[0])

        # git subcommands
        if prog == 'git' and len(tokens) > 1:
            return self._classify_git(tokens)

        # rm with flags / targets
        if prog == 'rm':
            return self._classify_rm(tokens)

        # chmod numeric / symbolic
        if prog == 'chmod':
            return self._classify_chmod(tokens)

        # dd destructive usage
        if prog == 'dd':
            return self._classify_dd(tokens)

        # sed -i promotes to WRITE_LOCAL
        if prog == 'sed' and any(t.startswith('-i') for t in tokens):
            return RiskClass.WRITE_LOCAL, CLASS_BASE_SCORE[RiskClass.WRITE_LOCAL], "sed_inplace"

        # docker --privileged
        if prog in ('docker', 'podman'):
            return self._classify_docker(tokens)

        # kill -9 1 / init
        if prog in ('kill', 'pkill', 'killall'):
            return self._classify_kill(tokens)

        # curl/wget piped to shell handled by pattern layer; here it is NETWORK_FETCH
        # lookup
        cls = COMMAND_CLASSES.get(prog, RiskClass.UNKNOWN)
        score = CLASS_BASE_SCORE[cls]
        # Sensitive-path boost — now only for genuinely-secret paths (shadow,
        # id_rsa, credentials, authorized_keys). General system paths like
        # /etc/group or /var/log/app.log are handled by the (finer-grained)
        # L3 Path layer with read-vs-write context.
        if self._touches_secret_path(tokens):
            if cls in (RiskClass.WRITE_LOCAL, RiskClass.READ_ONLY):
                return (RiskClass.WRITE_SENSITIVE,
                        CLASS_BASE_SCORE[RiskClass.WRITE_SENSITIVE],
                        f"{prog}:secret_path")
        # Local rsync/scp without remote host → WRITE_LOCAL not NETWORK_FETCH
        if prog in ('rsync', 'scp', 'sftp') and not self._has_remote_host(tokens):
            return (RiskClass.WRITE_LOCAL,
                    CLASS_BASE_SCORE[RiskClass.WRITE_LOCAL],
                    f"{prog}:local_no_remote_host")
        return cls, score, f"db_lookup:{prog}"

    # ------------- Specialized classifiers -------------

    def _classify_git(self, tokens) -> tuple[RiskClass, float, str]:
        sub = tokens[1] if len(tokens) > 1 else ''
        cls = GIT_SUBCOMMAND_CLASSES.get(sub, RiskClass.WRITE_LOCAL)
        # Destructive flags
        if sub == 'push' and any(t in ('-f', '--force', '--force-with-lease') for t in tokens):
            return RiskClass.DESTRUCTIVE, 0.85, "git_push_force"
        if sub == 'reset' and '--hard' in tokens:
            return RiskClass.DESTRUCTIVE, 0.80, "git_reset_hard"
        if sub == 'clean' and any(t.startswith('-f') or t.startswith('-d') for t in tokens):
            return RiskClass.DESTRUCTIVE, 0.70, "git_clean_force"
        return cls, CLASS_BASE_SCORE[cls], f"git_{sub}"

    def _classify_rm(self, tokens) -> tuple[RiskClass, float, str]:
        flags = [t for t in tokens[1:] if t.startswith('-')]
        fstr = ' '.join(flags)
        recursive = any(x in fstr for x in ('-r', '-R', '--recursive'))
        force = '-f' in fstr or '--force' in fstr
        targets = [t for t in tokens[1:] if not t.startswith('-')]

        if (recursive and force) or '-rf' in fstr or '-fr' in fstr:
            for p in targets:
                if p in ('/', '/*', '~', '~/*', '/home', '/etc', '/usr', '/var', '/boot', '/bin', '/sbin'):
                    return RiskClass.DESTRUCTIVE, 1.0, f"rm_rf_critical:{p}"
            return RiskClass.DESTRUCTIVE, 0.9, "rm_rf"
        if recursive:
            return RiskClass.DESTRUCTIVE, 0.7, "rm_recursive"
        return RiskClass.WRITE_LOCAL, 0.3, "rm_files"

    def _classify_chmod(self, tokens) -> tuple[RiskClass, float, str]:
        for t in tokens[1:]:
            if t.startswith('-'):
                continue
            if re.match(r'^[0-7]{3,4}$', t):
                mode_str = t[-3:]
                mode = int(mode_str, 8)
                paths = [p for p in tokens[2:] if not p.startswith('-')]
                is_sensitive = any(p.startswith(('/', '~/', '/etc', '/usr', '/bin', '/sbin')) for p in paths)
                if mode == 0o777 and is_sensitive:
                    return RiskClass.PRIVILEGE_OR_PERMISSION, 0.95, "chmod_777_sensitive"
                if mode == 0o777:
                    return RiskClass.PRIVILEGE_OR_PERMISSION, 0.80, "chmod_777"
                if t.startswith('4') or t.startswith('2'):   # SUID/SGID
                    return RiskClass.PRIVILEGE_OR_PERMISSION, 0.85, f"chmod_suid:{t}"
            # symbolic mode with +s
            if '+s' in t or 'u+s' in t or 'g+s' in t:
                return RiskClass.PRIVILEGE_OR_PERMISSION, 0.85, "chmod_setuid_sym"
            break
        return RiskClass.PRIVILEGE_OR_PERMISSION, 0.35, "chmod_normal"

    def _classify_dd(self, tokens) -> tuple[RiskClass, float, str]:
        joined = ' '.join(tokens)
        if re.search(r'of=/dev/(sd|hd|nvme|vd|md|mmcblk|loop)', joined):
            return RiskClass.DESTRUCTIVE, 1.0, "dd_block_device"
        if re.search(r'of=/dev/(zero|null)', joined):
            return RiskClass.READ_ONLY, 0.1, "dd_to_null"
        return RiskClass.DESTRUCTIVE, 0.6, "dd_generic"

    def _classify_docker(self, tokens) -> tuple[RiskClass, float, str]:
        if 'run' in tokens and '--privileged' in tokens:
            return RiskClass.PRIVILEGE_OR_PERMISSION, 0.90, "docker_privileged"
        if any(t in tokens for t in ('ps', 'images', 'logs', 'inspect')):
            return RiskClass.READ_ONLY, 0.0, "docker_read"
        return RiskClass.WRITE_LOCAL, CLASS_BASE_SCORE[RiskClass.WRITE_LOCAL], "docker_other"

    def _classify_kill(self, tokens) -> tuple[RiskClass, float, str]:
        joined = ' '.join(tokens)
        if re.search(r'\bkill\s+-9?\s+(-?1|\$\$)\b', joined):
            return RiskClass.RESOURCE_ABUSE, 0.95, "kill_init"
        if re.search(r'\bkillall\s+(sshd|init|systemd|dbus)\b', joined):
            return RiskClass.RESOURCE_ABUSE, 0.90, "killall_critical"
        if re.search(r'\bpkill\s+-9\s+-u\s+root\b', joined):
            return RiskClass.RESOURCE_ABUSE, 0.90, "pkill_root"
        return RiskClass.RESOURCE_ABUSE, CLASS_BASE_SCORE[RiskClass.RESOURCE_ABUSE], "kill_generic"

    def _touches_secret_path(self, tokens) -> bool:
        """Narrow to genuinely-secret paths only (shadow, id_rsa, credentials).
        Previously this included /etc/, /var/log/ etc. which caused false
        positives on benign reads (find, cat /etc/group, tail -f /var/log/...)."""
        secret = (
            '/etc/shadow', '/etc/gshadow', '/etc/sudoers',
            '~/.ssh/id_', '~/.ssh/authorized_keys',
            '~/.aws/credentials', '~/.docker/config.json',
            '~/.kube/config', '~/.gnupg/', '~/.netrc',
            '/root/.ssh',
            '.bash_history', '.zsh_history', '.mysql_history',
        )
        joined = ' '.join(tokens[1:]) if len(tokens) > 1 else ''
        return any(s in joined for s in secret)

    def _has_remote_host(self, tokens) -> bool:
        """True if any token looks like user@host:path (indicates remote
        rsync/scp/sftp)."""
        joined = ' '.join(tokens[1:]) if len(tokens) > 1 else ''
        return bool(re.search(r'\b[\w.-]+@[\w.-]+:', joined))
