"""L4 — High-confidence dangerous-pattern detection.

~80 provenance-tagged regex rules covering F1-F7 failure families.
Each rule carries:
  rule_id            SE-P-NNN
  pattern            compiled regex
  failure_family     F1..F7
  confidence         [0, 1]
  provenance_tier    'mitre' | 'gtfobins' | 'shellcheck' | 'owasp' | 'cve' | 'manual'
  mitre_techniques   list of T-IDs
  description        short human-readable label

`rule_provenance.json` is auto-derived from PATTERN_RULES at build time.
"""
import os
import re
import json

from .canonicalization import normalize as obfuscation_normalize


# -------------------------------------------------------------------------
# Rule definitions. One tuple per rule — no runtime mutation below.
# (rule_id, pattern, failure_family, confidence, provenance_tier, mitre_techniques, description)
# -------------------------------------------------------------------------
PATTERN_RULES_SPEC = [

    # F1 — Destructive execution
    ('SE-P-001', r'\brm\s+-[a-zA-Z]*rf[a-zA-Z]*\s+/(\s|$|\*)', 'F1', 1.0,  'mitre', ['T1485','T1070.004'], 'rm -rf /'),
    ('SE-P-002', r'\brm\s+-[a-zA-Z]*rf[a-zA-Z]*\s+(~/?|\$HOME)(\s|$|/\*)', 'F1', 0.95, 'mitre', ['T1485'], 'rm -rf ~'),
    ('SE-P-003', r'\brm\s+-[a-zA-Z]*rf[a-zA-Z]*\s+(/home|/etc|/usr|/var|/boot|/bin|/sbin|/opt)\b', 'F1', 0.95, 'mitre', ['T1485'], 'rm -rf on system dir'),
    ('SE-P-004', r'\brm\s+-[a-zA-Z]*rf[a-zA-Z]*\s+--no-preserve-root', 'F1', 1.0,  'mitre', ['T1485'], 'rm -rf --no-preserve-root'),
    ('SE-P-005', r'\bdd\s+if=/dev/(zero|urandom|random)\s+of=/dev/(sd|hd|nvme|vd|md|mmcblk)', 'F1', 1.0,  'mitre', ['T1485','T1561'], 'dd wipe to block device'),
    ('SE-P-006', r'\bmkfs(\.\w+)?\s+/dev/(sd|hd|nvme|vd)', 'F1', 1.0,  'mitre', ['T1485','T1561'], 'mkfs on block device'),
    ('SE-P-007', r'>\s*/dev/(sd|hd|nvme|vd|mmcblk)[a-z]\w*', 'F1', 1.0,  'mitre', ['T1485'], 'redirect to block device'),
    ('SE-P-008', r'\bshred\s+(-[a-zA-Z]*\s+)?/dev/(sd|hd|nvme)', 'F1', 1.0,  'mitre', ['T1485'], 'shred block device'),
    ('SE-P-009', r'\bwipefs\s+(-a\s+)?/dev/', 'F1', 1.0,  'mitre', ['T1485'], 'wipefs filesystem signatures'),
    ('SE-P-010', r'\bfind\s+/\s+.*-delete\b', 'F1', 0.85, 'manual', [], 'find / -delete'),
    ('SE-P-011', r'>\s*/(etc|boot)/\S+', 'F1', 0.85, 'mitre', ['T1485','T1070'], 'redirect overwrite to system config'),
    ('SE-P-012', r'\btruncate\s+-s\s*0\s+/etc/', 'F1', 0.9,  'mitre', ['T1485'], 'truncate system file'),

    # F2 — Workspace escape / exfil prep / suspicious discovery
    ('SE-P-013', r'\bfind\s+/\s+.*-type\s+f.*-name\s+["\']\*(env|key|secret|cred)',  'F2', 0.75, 'gtfobins', [], 'find secrets globally'),
    ('SE-P-014', r'\.\./\.\./\.\./',                                                  'F2', 0.65, 'manual', [], 'deep path traversal'),
    ('SE-P-015', r'\bchroot\s+/',                                                      'F2', 0.70, 'manual', [], 'chroot escape'),

    # F3 — Credential / secret exposure
    ('SE-P-016', r'\bcat\s+/etc/shadow\b',                           'F3', 1.0,  'mitre', ['T1552.001','T1003.008'], 'cat /etc/shadow'),
    ('SE-P-017', r'\bcat\s+/etc/passwd\b',                           'F3', 0.75, 'mitre', ['T1087.001'], 'cat /etc/passwd'),
    ('SE-P-018', r'\bcat\s+~/\.ssh/(id_rsa|id_ed25519|id_ecdsa|id_dsa)\b', 'F3', 1.0,  'mitre', ['T1552.004'], 'ssh private key read'),
    ('SE-P-019', r'\bcat\s+~/\.aws/credentials\b',                   'F3', 1.0,  'mitre', ['T1552.001'], 'AWS credentials read'),
    ('SE-P-020', r'\bcat\s+~/\.docker/config\.json\b',               'F3', 0.9,  'mitre', ['T1552.001'], 'Docker config read'),
    ('SE-P-021', r'\bcat\s+~/\.netrc\b',                             'F3', 0.9,  'mitre', ['T1552.004'], 'netrc credentials read'),
    ('SE-P-022', r'\bcat\s+(~/\.bash_history|~/\.zsh_history)\b',    'F3', 0.85, 'mitre', ['T1552.003'], 'shell history read'),
    ('SE-P-023', r'\bhistory\s+-c\s*(\s*&\s*&|;|\n).*>\s*~/\.bash_history', 'F3', 0.85, 'mitre', ['T1070.003'], 'history clear and overwrite'),
    ('SE-P-024', r'(scp|rsync)\s+.*/etc/(shadow|passwd|sudoers)\s+\S+@',          'F3', 1.0,  'mitre', ['T1048'], 'exfiltrate system creds'),
    ('SE-P-025', r'(curl|wget)\s+.*--data(-binary)?\s+@?/etc/(shadow|passwd)',   'F3', 0.95, 'mitre', ['T1048.003'], 'upload creds via curl/wget'),
    ('SE-P-026', r'\btar\s+c[a-z]*f?\s+-\s+.*/etc/\s*\|\s*(curl|wget|nc)',        'F3', 0.95, 'mitre', ['T1048'], 'tar pipe to exfil'),
    ('SE-P-027', r'\b(scp|rsync)\s+-r?\s+~/\.ssh\s+\S+@',                         'F3', 0.95, 'mitre', ['T1552.004'], 'exfiltrate ssh keys'),
    ('SE-P-028', r'\bgrep\s+-[a-zA-Z]*r[a-zA-Z]*\s+["\'](?:password|token|api[_-]?key|secret)',     'F3', 0.75, 'manual', [], 'grep for secrets'),
    ('SE-P-029', r'\bhexdump\s+.*\.gnupg',                                        'F3', 0.85, 'mitre', ['T1552'], 'dump gpg keyring'),
    ('SE-P-030', r'\bxxd\s+/etc/shadow',                                          'F3', 0.95, 'mitre', ['T1003.008'], 'xxd shadow'),

    # F4 — Download-and-execute
    ('SE-P-031', r'(curl|wget)\s+[^|;&]*\|\s*(bash|sh|zsh|dash)\b',                'F4', 1.0,  'mitre', ['T1105','T1059.004'], 'curl/wget | shell'),
    ('SE-P-032', r'(curl|wget)\s+[^|;&]*\|\s*sudo\s+(bash|sh)',                    'F4', 1.0,  'mitre', ['T1105'], 'curl/wget | sudo shell'),
    ('SE-P-033', r'bash\s+<\s*\(\s*(curl|wget)',                                   'F4', 1.0,  'mitre', ['T1105'], 'bash <(curl/wget)'),
    ('SE-P-034', r'source\s+<\s*\(\s*(curl|wget)',                                 'F4', 1.0,  'mitre', ['T1105'], 'source <(curl/wget)'),
    ('SE-P-035', r'(curl|wget)\s+.*-[a-zA-Z]*o\s+\S+\s*&&\s*chmod\s+\+x\s+\S+\s*&&\s*\./?\S+', 'F4', 0.95, 'mitre', ['T1105'], 'download -> chmod +x -> run'),
    ('SE-P-036', r'bash\s+-c\s+["\'\$]\(\s*(curl|wget)',                            'F4', 0.95, 'mitre', ['T1105'], 'bash -c $(curl ...)'),
    ('SE-P-037', r'eval\s+["\'\$]\(\s*(curl|wget)',                                 'F4', 0.95, 'mitre', ['T1105','T1059.004'], 'eval $(curl ...)'),
    ('SE-P-038', r'python[23]?\s+-c\s+["\'].*urllib.*\b(urlopen|Request).*\bexec\s*\(', 'F4', 0.95, 'mitre', ['T1105','T1059.006'], 'python urllib exec'),
    ('SE-P-039', r'python[23]?\s+-c\s+["\'].*requests\.get.*\bexec\s*\(',           'F4', 0.95, 'mitre', ['T1105','T1059.006'], 'python requests exec'),
    ('SE-P-040', r'perl\s+-e\s+["\'].*use\s+LWP.*system\s*\(',                      'F4', 0.95, 'mitre', ['T1105'], 'perl LWP system'),

    # F5 — Persistence
    ('SE-P-041', r'(echo|printf)\s+[^|]*\|\s*crontab\s+-',                          'F5', 1.0,  'mitre', ['T1053.003'], 'echo | crontab -'),
    ('SE-P-042', r'\bcrontab\s+-[eul]?\s*$',                                        'F5', 0.65, 'mitre', ['T1053.003'], 'crontab edit'),
    ('SE-P-043', r'>>\s*/etc/cron\.\w+/',                                            'F5', 1.0,  'mitre', ['T1053.003'], 'append to /etc/cron.*'),
    ('SE-P-044', r'>>\s*~/\.(bashrc|profile|bash_profile|zshrc|zprofile)',          'F5', 0.85, 'mitre', ['T1546.004'], 'append to shell rc'),
    ('SE-P-045', r'>>\s*/etc/(rc\.local|profile|bashrc)\b',                          'F5', 0.95, 'mitre', ['T1037'], 'append to system init'),
    ('SE-P-046', r'(echo|printf|cat)\s+[^|]*ssh-(rsa|ed25519|ecdsa)\s+[^|]*\s*>>\s*~?/?\.?ssh/authorized_keys', 'F5', 1.0, 'mitre', ['T1098.004'], 'add SSH key to authorized_keys'),
    ('SE-P-047', r'\bln\s+-sf?\s+\S+\s+/etc/cron\.',                                 'F5', 0.95, 'mitre', ['T1053.003'], 'symlink into /etc/cron.*'),
    ('SE-P-048', r'\bsystemctl\s+enable\s+\S+\.service',                             'F5', 0.55, 'mitre', ['T1543.002'], 'systemctl enable unit'),
    ('SE-P-049', r'>\s*/etc/systemd/system/\S+\.service\b',                          'F5', 0.95, 'mitre', ['T1543.002'], 'write systemd unit'),
    ('SE-P-050', r'\binstall\s+.*\bPreLoad\b|\bLD_PRELOAD\b=\S+.*\$SHELL',           'F5', 0.90, 'mitre', ['T1574.006'], 'LD_PRELOAD hijack'),
    ('SE-P-051', r'\becho\s+\S+\s*>>\s*/etc/ld\.so\.preload\b',                      'F5', 0.95, 'mitre', ['T1574.006'], 'ld.so.preload write'),
    ('SE-P-052', r'\bat\s+(now|\+\d+).*<',                                            'F5', 0.65, 'mitre', ['T1053.001'], 'at-job scheduling'),

    # F6 — Permission broadening
    ('SE-P-053', r'\bchmod\s+0?7?777\s+/',                                            'F6', 0.95, 'mitre', ['T1222.002'], 'chmod 777 on root-level path'),
    ('SE-P-054', r'\bchmod\s+0?7?777\s+/etc/\S+',                                     'F6', 0.95, 'mitre', ['T1222.002'], 'chmod 777 /etc/*'),
    ('SE-P-055', r'\bchmod\s+[24][0-7]{3}\b',                                         'F6', 0.85, 'mitre', ['T1548.001'], 'chmod SUID/SGID numeric'),
    ('SE-P-056', r'\bchmod\s+(\+s|u\+s|g\+s)\b',                                      'F6', 0.90, 'mitre', ['T1548.001'], 'chmod +s setuid'),
    ('SE-P-057', r'\bchown\s+(root|0)(:|\s)',                                          'F6', 0.55, 'manual', [], 'chown to root'),
    ('SE-P-058', r'\bsetcap\s+\S*cap_\S+\s+\S+',                                      'F6', 0.85, 'mitre', ['T1548'], 'setcap capability grant'),
    ('SE-P-059', r'NOPASSWD\s*:\s*ALL',                                               'F6', 1.0,  'mitre', ['T1548.003'], 'NOPASSWD sudo rule'),
    ('SE-P-060', r'(echo|printf)\s+[^|]*NOPASSWD[^|]*>>\s*/etc/sudoers',               'F6', 1.0,  'mitre', ['T1548.003'], 'append NOPASSWD to sudoers'),
    ('SE-P-061', r'\busermod\s+-a?G\s+(sudo|wheel|admin|root)\b',                      'F6', 0.85, 'mitre', ['T1136.001'], 'add user to privileged group'),
    ('SE-P-062', r'\buseradd\s+.*-u\s*0\b',                                            'F6', 0.95, 'mitre', ['T1136.001'], 'create UID-0 user'),
    ('SE-P-063', r'\bpasswd\s+root\b',                                                 'F6', 0.75, 'mitre', ['T1098'], 'reset root password'),

    # F7 — Resource abuse / impact
    ('SE-P-064', r':\s*\(\s*\)\s*\{[^}]*:\s*\|\s*:\s*&[^}]*\}[^:]*:',                 'F7', 1.0,  'mitre', ['T1499.001'], 'classic fork bomb'),
    ('SE-P-065', r'\(\s*\)\s*\{\s*\$0\s*\|\s*\$0',                                     'F7', 0.95, 'mitre', ['T1499.001'], 'fork-bomb variant'),
    ('SE-P-066', r'\bkill\s+-9?\s+(-?1|\$\$|0)\b',                                      'F7', 0.95, 'mitre', ['T1489'], 'kill init or self-session'),
    ('SE-P-067', r'\bkillall\s+(sshd|init|systemd|dbus)\b',                            'F7', 0.95, 'mitre', ['T1489'], 'killall critical daemons'),
    ('SE-P-068', r'\bpkill\s+-9?\s+-u\s+root\b',                                        'F7', 0.90, 'mitre', ['T1489'], 'pkill root-owned processes'),
    ('SE-P-069', r'\b(shutdown|reboot|halt|poweroff)\b(?!\s+--help)',                   'F7', 0.75, 'mitre', ['T1529'], 'system shutdown/reboot'),
    ('SE-P-070', r'while\s+(true|:)\s*;\s*do\s+dd\s+if=/dev/(zero|urandom)\s+of=',    'F7', 0.95, 'mitre', ['T1499.001'], 'infinite dd loop (disk fill)'),
    ('SE-P-071', r'\bfallocate\s+-l\s+\d+[TGM]\s+/tmp/',                                'F7', 0.80, 'manual', [], 'fallocate large'),
    ('SE-P-072', r'\byes\s+>\s*/dev/null\s*&',                                          'F7', 0.85, 'mitre', ['T1499.001'], 'yes > /dev/null & (CPU-spin DoS)'),
    ('SE-P-073', r'\bstress(-ng)?\s+--(cpu|vm|io)',                                     'F7', 0.70, 'manual', [], 'stress load generator'),
    ('SE-P-074', r'\bhping3\b.*--flood',                                               'F7', 0.85, 'mitre', ['T1499'], 'hping3 flood'),

    # F8-related — obfuscated forms that nevertheless fire deterministically
    ('SE-P-075', r'\bbase64\s+(-d|--decode)\b[^|]*\|\s*(bash|sh|zsh|eval)',             'F1', 0.95, 'mitre', ['T1027','T1059.004'], 'base64 decode | shell'),
    ('SE-P-076', r'\beval\s+["\']?\$\s*\(\s*(echo\s+[A-Za-z0-9+/=]+\s*\|\s*base64\s+-d)', 'F1', 0.95, 'mitre', ['T1027'], 'eval $(base64 decode)'),
    ('SE-P-077', r'printf\s+["\']?(\\\\x[0-9a-fA-F]{2}){4,}["\']?\s*\|\s*(bash|sh)',     'F1', 0.90, 'mitre', ['T1027.002'], 'printf hex | shell'),
    ('SE-P-078', r'\brev\s*\|\s*(bash|sh)\b',                                           'F1', 0.90, 'manual', [], 'rev | shell'),
    ('SE-P-079', r'\bxxd\s+-r\s+-p\b[^|]*\|\s*(bash|sh)',                               'F1', 0.90, 'mitre', ['T1027'], 'xxd -r -p | shell'),
    ('SE-P-080', r'\$\(\s*printf\s+["\']?\\\\x[0-9a-fA-F]{2}',                          'F1', 0.75, 'mitre', ['T1027.002'], 'hex printf substitution'),

    # Reverse shell / network back-channel (maps to F2 workspace escape by taxonomy)
    ('SE-P-081', r'bash\s+-i\s+>&\s*/dev/tcp/',                                         'F2', 1.0,  'mitre', ['T1059.004','T1071.001'], 'bash reverse shell'),
    ('SE-P-082', r'\bnc\s+(-[a-zA-Z]*e|--exec)\s+/bin/(ba)?sh',                         'F2', 1.0,  'mitre', ['T1059.004'], 'nc -e reverse shell'),
    ('SE-P-083', r'python[23]?\s+-c\s+["\'][^"\']*socket\.socket[^"\']*connect[^"\']*dup2', 'F2', 0.95, 'mitre', ['T1059.006'], 'python socket reverse shell'),
    ('SE-P-084', r'(mknod|mkfifo)\s+\S+\s+p\b',                                          'F2', 0.75, 'manual', [], 'named pipe (fifo) for callback'),

    # Extended F4 coverage (addresses coverage gaps on script-staging and
    # language-level interpreter abuse revealed by the F4 extended set)
    ('SE-P-085', r'chmod\s+\+x\s+\S+\.sh\b.*\n?.*\bbash\s+\S+\.sh',                     'F4', 0.85, 'mitre', ['T1059.004','T1105'], 'chmod+x then bash script staging'),
    ('SE-P-086', r'awk\s+["\']BEGIN\s*\{[^}]*system\s*\(',                              'F4', 0.90, 'mitre', ['T1059.004'], 'awk BEGIN system call'),
    ('SE-P-087', r'perl\s+-MIO::Socket\b',                                              'F4', 0.90, 'mitre', ['T1059.006'], 'perl IO::Socket inline module'),
    ('SE-P-088', r'(echo|printf)\s+\$\S+\s*\|\s*(/bin/)?(sh|bash)\b',                   'F4', 0.85, 'mitre', ['T1059.004'], 'env-var echo pipe to shell'),
    ('SE-P-089', r'python[23]?\s+-c\s+["\'][^"\']*urllib.*os\.system',                  'F4', 0.95, 'mitre', ['T1105','T1059.006'], 'python urllib + os.system'),
    ('SE-P-090', r'\$\(\s*curl\b[^)]*\)\s*\|\s*xargs\s+[^|]*\bbash\s+-c',               'F4', 0.90, 'manual', [], 'curl substitution piped to xargs bash'),
    ('SE-P-091', r'eval\s+["\']?\$\s*\(\s*wget\b',                                      'F4', 0.95, 'mitre', ['T1105'], 'eval wget fetch output'),
    ('SE-P-092', r'sh\s+<\s*\(\s*(curl|wget)',                                          'F4', 1.00, 'mitre', ['T1105'], 'sh <(curl/wget) process sub'),
    ('SE-P-093', r'(curl|wget)\b[^|]*\|\s*sudo\s+-E?\s*bash\b',                         'F4', 1.00, 'mitre', ['T1105'], 'curl/wget | sudo -E bash'),

    # Extended F7 coverage (fork-bomb generic form, service stops, disk fill)
    ('SE-P-094', r'(\w+)\s*\(\s*\)\s*\{\s*\1\s*\|\s*\1\s*&\s*\}\s*;\s*\1',              'F7', 0.95, 'mitre', ['T1499.001'], 'generic named fork bomb'),
    ('SE-P-095', r'perl\s+-e\s+["\']?fork\s+while\s+\d',                                'F7', 0.95, 'mitre', ['T1499.001'], 'perl fork while loop'),
    ('SE-P-096', r'python[23]?\s+-c\s+["\'][^"\']*os\.fork\b',                          'F7', 0.90, 'mitre', ['T1499.001'], 'python os.fork loop'),
    ('SE-P-097', r'systemctl\s+(stop|disable|mask)\s+(cron|sshd|firewalld|ufw|auditd|rsyslog)\b', 'F7', 0.90, 'mitre', ['T1489'], 'systemctl stop critical daemon'),
    ('SE-P-098', r'\bhead\s+-c\s+\d+[TG]\s+<\s*/dev/(zero|urandom|random)\s*>\s*',      'F7', 0.90, 'manual', [], 'head -c huge → file (disk fill)'),
    ('SE-P-099', r'ulimit\s+-u\s+unlimited\s*;\s*while\s+(true|:)',                     'F7', 0.85, 'manual', [], 'ulimit -u unlimited + infinite loop'),
    ('SE-P-100', r'\b(dscl\s+\S+\s+-delete\s+/Users/|sysadminctl\s+-deleteUser)\b',     'F7', 0.85, 'mitre', ['T1531'], 'macOS user account delete'),
    ('SE-P-101', r'(yes\s+>\s*/dev/null\s+&\s+){2,}',                                   'F7', 0.80, 'manual', [], 'multi-instance yes > /dev/null'),

    # Extended F3 credential-reconnaissance patterns
    ('SE-P-102', r'\b(cat|less|more|head|tail|xxd|strings|grep|awk|sed)\s+[^|;&]*/etc/(pam\.d/|security/|login\.defs|passwd\b|group\b)', 'F3', 0.80, 'mitre', ['T1201','T1087.001'], 'Password-policy / account discovery read'),
    ('SE-P-103', r'\b(scp|rsync|sftp)\s+[^|]*\b[\w.-]+@[\w.-]+:',                        'F3', 0.75, 'mitre', ['T1105','T1048'], 'Cross-host file transfer (exfil/ingress)'),
    ('SE-P-104', r'\bexport\s+(https?_proxy|HTTPS?_PROXY)=\S+:\d+',                      'F3', 0.70, 'mitre', ['T1090.001'], 'HTTP proxy hijack for traffic interception'),
    ('SE-P-105', r'\bnetworksetup\s+-set(web|secure|socks)proxy\b',                      'F3', 0.80, 'mitre', ['T1090.001'], 'macOS network proxy redirect'),
    ('SE-P-106', r'\becho\s+-e\s+["\'][^"\']*\be\s+/etc/(passwd|shadow)[^"\']*["\']\s*\|\s*ed',   'F3', 0.85, 'mitre', ['T1003.008'], 'ed in-place editor dump of passwd/shadow'),

    # GTFOBins dual-use lexicon — F2 shell spawn via non-shell binary
    ('SE-P-107', r'\b(tmate|genie|setarch|ssh-agent|bundle\s+exec|ranger|crash|vagrant)\s+(-c\s+[\'"]?)?/bin/(ba|da|z)?sh\b',                    'F2', 0.90, 'gtfobins', ['T1059.004'], 'dual-use binary spawns /bin/sh'),
    ('SE-P-108', r'\bfind\s+[^|;]{0,80}-exec\s+/bin/(ba)?sh\b',                                                                                 'F2', 0.90, 'gtfobins', ['T1059.004'], 'find -exec /bin/sh'),
    ('SE-P-109', r'\b(SYSTEMD_EDITOR|SYSTEMD_PAGER|CRASHPAGER|EDITOR|VISUAL|PAGER)=[^\s]+\s+(systemctl\s+edit|sudoedit|crash|less|more|man|view)\b', 'F2', 0.80, 'gtfobins', ['T1548.003'], 'EDITOR/PAGER env override + privileged invoker'),
    ('SE-P-110', r'\b(php|ruby|perl)\s+-[rec]\s+[\'"][^\'"]*\b(shell_exec|system|exec|Kernel\.(exec|system)|Process\.spawn|passthru|popen|proc_open)\s*\(\s*[\'"][^\'"]*(/bin/(ba)?sh|\$)', 'F2', 0.90, 'gtfobins', ['T1059.004','T1059.006'], 'interpreter inline shell spawn'),
    ('SE-P-111', r'--config\s+alias\.[a-zA-Z0-9_]+=[\'"]?!\s*/bin/(ba)?sh|alias\.[a-zA-Z0-9_]+=[\'"]?!\s*/bin/(ba)?sh',                         'F2', 0.90, 'gtfobins', ['T1059.004'], 'hg/git config alias injects !/bin/sh'),
    ('SE-P-112', r'\bdocker\s+run\s+[^|;]*--privileged\b',                                                                                      'F2', 0.80, 'gtfobins', ['T1611'], 'docker run --privileged (container escape)'),

    # GTFOBins — F2 reverse-shell patterns through dual-use interpreters
    ('SE-P-113', r'\b(gawk|awk|mawk)\s+[\'"]BEGIN\s*\{[^}]*/inet/tcp/',                                                                         'F2', 0.95, 'gtfobins', ['T1071.001','T1059.004'], 'awk BEGIN /inet/tcp (gawk reverse shell)'),
    ('SE-P-114', r'fsockopen\s*\([^)]+\)\s*[;)][\s\S]{0,120}\b(exec|system|passthru)\s*\([\'"]/bin/(ba)?sh',                                    'F2', 0.95, 'gtfobins', ['T1071.001','T1059.004'], 'PHP fsockopen + exec /bin/sh'),
    ('SE-P-115', r'\bTCPSocket\.new\s*\([\'"]?[\w.-]+[\'"]?\s*,\s*\d+\s*\)[\s\S]{0,200}(/bin/(ba|z)?sh|c\.gets)',                               'F2', 0.90, 'gtfobins', ['T1071.001','T1059.006'], 'Ruby TCPSocket + shell callback'),
    ('SE-P-116', r'\bmkfifo\s+\S+[\s\S]{0,200}\|\s*(nc|ncat|openssl|telnet|socat)\b',                                                           'F2', 0.90, 'gtfobins', ['T1071.001'], 'mkfifo + nc/openssl/telnet pipe'),
    ('SE-P-117', r'\bsocat\s+[^|]*(tcp[\-:]connect|tcp[0-9]*:)[^|]*exec:\s*[\'"]?/bin/(ba)?sh',                                                 'F2', 0.95, 'gtfobins', ['T1071.001','T1059.004'], 'socat tcp-connect + exec:/bin/sh'),

    # GTFOBins — F4 network-fetch / download abuse via dual-use utilities
    ('SE-P-118', r'\bsmbclient\s+[^|]*-c\s+[\'"](get|put)\s+/(etc|root|home|var)/',                                                             'F3', 0.90, 'gtfobins', ['T1105','T1048'], 'smbclient get/put system file'),
    ('SE-P-119', r'file:///+(etc/(shadow|passwd|sudoers|pam\.d)|root/|home/[^/]+/\.(ssh|aws|gnupg|docker|kube))',                               'F3', 0.95, 'gtfobins', ['T1552.001','T1003.008'], 'file:// scheme to secret path'),
    ('SE-P-120', r'\b(wget|curl|aria2c|lwp-download|ab)\s+[^|]*https?://[^\s]+/etc/(shadow|passwd|sudoers)\b',                                  'F3', 0.95, 'gtfobins', ['T1105','T1552.001'], 'HTTP fetch to system cred path'),
    ('SE-P-121', r'\bwhois\s+-h\s+[\w.-]+\s+-p\s+\d+\s+\S+',                                                                                   'F4', 0.75, 'gtfobins', ['T1071.001'], 'whois -h/-p exfil channel'),
    ('SE-P-122', r'\btftp\s+(-[a-z]+\s+)?[\w.-]+\s+(get|put)\s+/(etc|root|home)/',                                                              'F4', 0.90, 'gtfobins', ['T1105'], 'tftp get/put system path'),

    # GTFOBins — upload / exfil-listener patterns
    ('SE-P-123', r'\bnc\s+(-[a-zA-Z]*l[a-zA-Z]*|--listen)\s+[^|]*<\s*/(etc/(shadow|passwd|sudoers)|root/|home/[^/]+/\.(ssh|aws))',              'F3', 0.95, 'gtfobins', ['T1048'], 'nc listen redirecting from secret'),
    ('SE-P-124', r'(--address=0\.0\.0\.0|-S\s+0\.0\.0\.0:|--bind=0\.0\.0\.0|--listen=0\.0\.0\.0|kubectl\s+proxy\s+--address=0\.0\.0\.0)',       'F5', 0.75, 'gtfobins', ['T1090.001'], 'server listen on 0.0.0.0 all-interfaces'),
    ('SE-P-125', r'\bfinger\s+[a-zA-Z_][\w]*@[\w.-]+\b',                                                                                        'F4', 0.70, 'gtfobins', ['T1071.001'], 'finger remote exfil pattern'),

    # GTFOBins — interpreter file-write primitives (F4 staging / F3 exfil to disk)
    ('SE-P-126', r'\b(node|ruby|lua|python[23]?|perl|elvish|jrunscript|julia)\s+-[eEr]\s+[\'"][^\'"]*(writeFileSync|File\.open\s*\([^)]*,\s*[\'"]w|io\.open\s*\([^)]*,\s*[\'"]w|FileWriter|open\s*\([^)]*,\s*[\'"]w)', 'F4', 0.85, 'gtfobins', ['T1105','T1059.006'], 'interpreter inline file-write primitive'),
    ('SE-P-127', r'\bgdb\s+[^|]*-ex\s+[\'"]dump\s+(value|binary|memory)\b',                                                                     'F4', 0.90, 'gtfobins', ['T1005'], 'gdb dump value (memory exfil)'),
    ('SE-P-128', r'\bcpio\s+(-[a-z]*p[a-z]*\b|--pass-through)',                                                                                  'F4', 0.75, 'gtfobins', ['T1105'], 'cpio pass-through write'),
    ('SE-P-129', r'\bcurl\s+[^|]*file://[^\s]+\s+[^|]*-o\s+/(tmp|home|var/tmp|root)/',                                                          'F4', 0.85, 'gtfobins', ['T1005'], 'curl file:// + -o to writable dir'),
    ('SE-P-130', r'\b(rpm\s+-[Uivh]{1,3}\b[^|]*\.rpm|yum\s+localinstall\b|dnf\s+localinstall\b|pkg\s+install\s+[^|]*\./\S+\.(txz|pkg)|snap\s+install\b[^|]*--dangerous\b)', 'F4', 0.85, 'gtfobins', ['T1546.016','T1204.002'], 'local-file package install (arbitrary script)'),

    # GTFOBins — command-execution-via-option / config
    ('SE-P-131', r'\besyscmd\s*\(|\bsyscmd\s*\(',                                                                                                'F4', 0.90, 'gtfobins', ['T1059.004'], 'm4 esyscmd/syscmd builtin'),
    ('SE-P-132', r'--on-download-complete=\S+',                                                                                                  'F4', 0.85, 'gtfobins', ['T1059.004'], 'aria2c/wget on-download-complete handler'),
    ('SE-P-133', r'--(conf-script|exec-config|script-file)=[\'"]?\S*sh\b|\bdnsmasq\s+[^|]*--conf-script=',                                      'F4', 0.85, 'gtfobins', ['T1059.004'], '--conf-script= invokes external script'),
    ('SE-P-134', r'\bnohup\s+/(path/to|tmp|var/tmp|home/[^/]+/\.)\S+',                                                                           'F4', 0.70, 'gtfobins', ['T1059.004'], 'nohup executing writable-dir binary'),
    ('SE-P-135', r'\\verbatiminput\s*\{\s*/(etc|root|home)/|\\input\s*\{\s*/(etc|root)/',                                                        'F3', 0.85, 'gtfobins', ['T1552.001'], 'LaTeX \\verbatiminput of system file'),
    ('SE-P-136', r'\b(jjs|jrunscript)\s+[^|]*-e\s+[\'"][^\'"]*(Java\.type\s*\([\'"]java\.(net|io|lang\.ProcessBuilder))',                      'F4', 0.85, 'gtfobins', ['T1059.006','T1105'], 'jjs/jrunscript Java network or process primitive'),

    # Command injection — eval/exec on a positional parameter or user input var
    ('SE-P-137', r'\beval\s+["\']?\$\{?[1-9@*#]',                                                                                                'F2', 0.90, 'manual', ['T1059.004'], 'eval of positional parameter (command injection)'),
    ('SE-P-138', r'\beval\s+["\']?\$\{?(input|user|arg|cmd|query|param)\w*',                                                                     'F2', 0.75, 'manual', ['T1059.004'], 'eval of user-named variable (command injection)'),
    ('SE-P-139', r'\b(rm|dd|shred|truncate|unlink)\s+[^|;&\n]{0,60}?["\']?/usr/(?!local/)\S+',                                                    'F1', 0.85, 'manual', ['T1485'], 'destructive op on /usr/ system path'),
]


def _compile_rules():
    compiled = []
    for rid, pat, fam, conf, tier, mitre, desc in PATTERN_RULES_SPEC:
        compiled.append({
            'rule_id': rid,
            'pattern': re.compile(pat, re.IGNORECASE),
            'failure_family': fam,
            'confidence': conf,
            'provenance_tier': tier,
            'mitre_techniques': mitre,
            'description': desc,
        })
    return compiled


PROVENANCE_TIER_WEIGHT = {
    'mitre':    1.00,
    'cve':      0.90,
    'gtfobins': 0.85,
    'shellcheck': 0.80,
    'owasp':    0.80,
    'manual':   0.60,
}


class PatternDetector:
    """Return (score ∈ [0, 1], list[match_dict]) where match_dict has rule_id, family, confidence, provenance_weight."""

    def __init__(self):
        self.rules = _compile_rules()

    def detect(self, cmd: str) -> tuple[float, list]:
        """Match patterns on the command. When called from the analyzer the
        command has already been obfuscation-normalized at L0, so detection
        happens against the normalized form directly. A second normalization
        is a no-op on already-normalized input, so we skip it for latency.
        """
        matches = []
        best = 0.0
        search_targets = [('raw', cmd)]
        seen_ids = set()
        for r in self.rules:
            fired_on = None
            for tag, text in search_targets:
                if r['pattern'].search(text):
                    fired_on = tag
                    break
            if fired_on is None or r['rule_id'] in seen_ids:
                continue
            seen_ids.add(r['rule_id'])
            pw = PROVENANCE_TIER_WEIGHT[r['provenance_tier']]
            effective = pw * r['confidence']
            matches.append({
                'rule_id': r['rule_id'],
                'failure_family': r['failure_family'],
                'confidence': r['confidence'],
                'provenance_tier': r['provenance_tier'],
                'provenance_weight': pw,
                'effective_score': round(effective, 3),
                'description': r['description'],
                'via_normalizer': fired_on == 'normalized',
            })
            if effective > best:
                best = effective
        return best, matches


# ----- Artifact export -----
def export_rule_provenance(out_path: str) -> None:
    """Write rule_provenance.json artifact (Appendix A.4)."""
    records = []
    for rid, pat, fam, conf, tier, mitre, desc in PATTERN_RULES_SPEC:
        records.append({
            'rule_id': rid,
            'layer': 4,
            'description': desc,
            'failure_family': fam,
            'mitre_techniques': mitre,
            'shellcheck_ids': [],
            'owasp_category': 'A03:2021 Injection' if fam == 'F4' else None,
            'gtfobins_related': tier == 'gtfobins',
            'cve_examples': [],
            'confidence': conf,
            'provenance_tier': tier,
            'pattern_regex': pat,
        })
    with open(out_path, 'w') as f:
        json.dump({
            '_meta': {
                'description': 'CARE L4 rule provenance map',
                'total_rules': len(records),
                'version': '1.0',
                'date': '2026-04-15',
            },
            'rules': records,
        }, f, indent=2)


if __name__ == '__main__':
    here = os.path.dirname(os.path.abspath(__file__))
    out = os.path.join(here, 'rules', 'rule_provenance.json')
    export_rule_provenance(out)
    print(f'Wrote {out} with {len(PATTERN_RULES_SPEC)} rules')
