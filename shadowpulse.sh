#!/usr/bin/env bash
###############################################################################
# ShadowPulse — Linux Threat Hunting & Incident Response Toolkit
#
# Automated evidence collection, malware detection, persistence hunting,
# IOC extraction, and forensic reporting for Linux incident response.
#
# Author:  Ali AlEnezi (@SiteQ8) — Made in Kuwait
# License: MIT
# Version: 1.0.0
###############################################################################
set -euo pipefail

VERSION="1.0.0"
HOSTNAME=$(hostname 2>/dev/null || echo "unknown")
DATE_ISO=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
DATE_FS=$(date +"%Y%m%d-%H%M%S")
CASE_DIR="/var/shadowpulse/case-${DATE_FS}"
EVIDENCE_DIR="${CASE_DIR}/evidence"
HASHES_FILE="${CASE_DIR}/chain-of-custody.sha256"
REPORT_FILE="${CASE_DIR}/report.html"
FINDINGS=()
FINDING_COUNT=0
CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0
INFO_COUNT=0
MODULE_COUNT=0

# ─── Colors ──────────────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[0;33m'; B='\033[0;34m'
C='\033[0;36m'; W='\033[1;37m'; D='\033[0;90m'; N='\033[0m'; BOLD='\033[1m'

BANNER="${C}
   _____ __              __                ____        __
  / ___// /_  ____ _____/ /___ _      __  / __ \\__  __/ /___ ___
  \\__ \\/ __ \\/ __ \`/ __  / __ \\ | /| / / / /_/ / / / / / ___/ _ \\
 ___/ / / / / /_/ / /_/ / /_/ / |/ |/ / / ____/ /_/ / (__  )  __/
/____/_/ /_/\\__,_/\\__,_/\\____/|__/|__/ /_/    \\__,_/_/____/\\___/

${W}  Linux Threat Hunting & Incident Response Toolkit  v${VERSION}
${D}  github.com/SiteQ8/ShadowPulse — Made in Kuwait${N}
"

# ─── Utility Functions ───────────────────────────────────────────────
log_info()  { echo -e "  ${C}[INFO]${N}  $1"; }
log_pass()  { echo -e "  ${G}[PASS]${N}  $1"; }
log_warn()  { echo -e "  ${Y}[WARN]${N}  $1"; }
log_fail()  { echo -e "  ${R}[ALERT]${N} $1"; }
log_data()  { echo -e "  ${W}[DATA]${N}  $1"; }
log_hunt()  { echo -e "  ${R}[HUNT]${N}  $1"; }
section()   { echo -e "\n${BOLD}${C}═══ $1 ═══${N}"; ((MODULE_COUNT+=1)); }

add_finding() {
    local severity="$1" title="$2" detail="$3" remediation="${4:-}"
    FINDINGS+=("${severity}|${title}|${detail}|${remediation}")
    ((FINDING_COUNT+=1))
    case "$severity" in
        CRITICAL) ((CRITICAL_COUNT+=1)); log_fail "[CRITICAL] $title — $detail" ;;
        HIGH)     ((HIGH_COUNT+=1));     log_fail "[HIGH] $title — $detail" ;;
        MEDIUM)   ((MEDIUM_COUNT+=1));   log_warn "[MEDIUM] $title — $detail" ;;
        LOW)      ((LOW_COUNT+=1));      log_warn "[LOW] $title — $detail" ;;
        INFO)     ((INFO_COUNT+=1));     log_data "[INFO] $title — $detail" ;;
    esac
}

save_evidence() {
    local name="$1" cmd="$2"
    local outfile="${EVIDENCE_DIR}/${name}"
    eval "$cmd" > "$outfile" 2>/dev/null || true
    if [[ -s "$outfile" ]]; then
        sha256sum "$outfile" >> "$HASHES_FILE" 2>/dev/null || true
    fi
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${R}[ERROR]${N} ShadowPulse requires root privileges for forensic collection."
        echo -e "       Run with: sudo $0 $*"
        exit 1
    fi
}

show_help() {
    echo -e "$BANNER"
    cat << 'EOF'
Usage: sudo shadowpulse.sh [OPTIONS]

Modules:
  --all              Run all modules (default)
  --volatile         Volatile data collection (processes, connections, memory)
  --persistence      Persistence mechanism hunting (cron, systemd, SSH, init)
  --malware          Malware and webshell detection (signatures, heuristics)
  --users            User and authentication analysis (logins, sudoers, keys)
  --network          Network forensics (connections, DNS, ARP, firewall)
  --logs             Log analysis and anomaly detection
  --ioc              IOC extraction (IPs, domains, hashes, URLs)
  --timeline         Event timeline reconstruction

Options:
  --output DIR       Custom output directory (default: /var/shadowpulse/)
  --quiet            Suppress banner and progress output
  --no-report        Skip HTML report generation
  --help             Show this help message
  --version          Show version

Examples:
  sudo shadowpulse.sh                          # Full scan — all modules
  sudo shadowpulse.sh --volatile --network     # Only volatile + network
  sudo shadowpulse.sh --malware --persistence  # Hunt for threats
  sudo shadowpulse.sh --output /cases/inc-42   # Custom output path

Output:
  /var/shadowpulse/case-YYYYMMDD-HHMMSS/
  ├── evidence/           # Raw collected artifacts
  ├── chain-of-custody.sha256   # SHA-256 hashes of all evidence
  └── report.html         # Forensic investigation report
EOF
    exit 0
}

# ─── Parse Arguments ─────────────────────────────────────────────────
RUN_ALL=true
RUN_VOLATILE=false; RUN_PERSISTENCE=false; RUN_MALWARE=false
RUN_USERS=false; RUN_NETWORK=false; RUN_LOGS=false
RUN_IOC=false; RUN_TIMELINE=false
QUIET=false; NO_REPORT=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --all)         RUN_ALL=true ;;
        --volatile)    RUN_ALL=false; RUN_VOLATILE=true ;;
        --persistence) RUN_ALL=false; RUN_PERSISTENCE=true ;;
        --malware)     RUN_ALL=false; RUN_MALWARE=true ;;
        --users)       RUN_ALL=false; RUN_USERS=true ;;
        --network)     RUN_ALL=false; RUN_NETWORK=true ;;
        --logs)        RUN_ALL=false; RUN_LOGS=true ;;
        --ioc)         RUN_ALL=false; RUN_IOC=true ;;
        --timeline)    RUN_ALL=false; RUN_TIMELINE=true ;;
        --output)      shift; CASE_DIR="$1/case-${DATE_FS}"; EVIDENCE_DIR="${CASE_DIR}/evidence"; HASHES_FILE="${CASE_DIR}/chain-of-custody.sha256"; REPORT_FILE="${CASE_DIR}/report.html" ;;
        --quiet)       QUIET=true ;;
        --no-report)   NO_REPORT=true ;;
        --help|-h)     show_help ;;
        --version|-v)  echo "ShadowPulse v${VERSION}"; exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
    shift
done

if $RUN_ALL; then
    RUN_VOLATILE=true; RUN_PERSISTENCE=true; RUN_MALWARE=true
    RUN_USERS=true; RUN_NETWORK=true; RUN_LOGS=true
    RUN_IOC=true; RUN_TIMELINE=true
fi

# ─── Initialize ──────────────────────────────────────────────────────
check_root
$QUIET || echo -e "$BANNER"

mkdir -p "$EVIDENCE_DIR"
echo "# ShadowPulse Chain of Custody — ${DATE_ISO}" > "$HASHES_FILE"
echo "# Hostname: ${HOSTNAME}" >> "$HASHES_FILE"
echo "# Investigator: $(whoami)@${HOSTNAME}" >> "$HASHES_FILE"
echo "" >> "$HASHES_FILE"

log_info "Case directory: ${CASE_DIR}"
log_info "Timestamp: ${DATE_ISO}"
log_info "System: ${HOSTNAME} ($(uname -r))"

# System metadata
save_evidence "system-info.txt" "echo 'Hostname: ${HOSTNAME}'; echo 'Kernel: $(uname -a)'; echo 'Uptime: $(uptime)'; echo 'Date: ${DATE_ISO}'; cat /etc/os-release 2>/dev/null"


###############################################################################
# MODULE 1: VOLATILE DATA COLLECTION
###############################################################################
if $RUN_VOLATILE; then
section "MODULE 1: VOLATILE DATA COLLECTION"

# Running processes — full tree
save_evidence "processes-tree.txt" "ps auxwwf"
save_evidence "processes-full.txt" "ps -eo pid,ppid,user,uid,gid,stat,ni,vsz,rss,%cpu,%mem,wchan,tty,start,time,comm,args --sort=-%cpu"
log_data "Process tree captured ($(ps aux | wc -l) processes)"

# Process ancestry — detect orphan/reparented processes
save_evidence "process-parents.txt" "ps -eo pid,ppid,comm,args --sort=ppid"
orphans=$(ps -eo ppid | grep -c "^\s*1$" 2>/dev/null || echo "0")
if [[ "$orphans" -gt 20 ]]; then
    add_finding "MEDIUM" "High orphan process count" "${orphans} processes parented to init/systemd" "Review processes reparented to PID 1 for potential process injection"
fi

# Open files and file descriptors
save_evidence "open-files.txt" "lsof -nP 2>/dev/null | head -5000"
save_evidence "deleted-files-open.txt" "lsof -nP 2>/dev/null | grep '(deleted)'"
deleted_count=$(lsof -nP 2>/dev/null | grep -c "(deleted)" || echo "0")
if [[ "$deleted_count" -gt 0 ]]; then
    add_finding "HIGH" "Deleted files still open" "${deleted_count} deleted files held open by running processes" "Investigate deleted-but-open files — common malware evasion technique"
fi

# Memory maps of suspicious processes
save_evidence "proc-maps-summary.txt" "for pid in \$(ps -eo pid --no-headers | head -100); do echo \"=== PID \$pid ===\"; cat /proc/\$pid/cmdline 2>/dev/null | tr '\\0' ' '; echo; cat /proc/\$pid/maps 2>/dev/null | grep -c 'rwx' || true; done"

# Loaded kernel modules
save_evidence "kernel-modules.txt" "lsmod"
save_evidence "kernel-modules-detail.txt" "cat /proc/modules"
unsigned_mods=$(lsmod | awk 'NR>1{print $1}' | while read mod; do modinfo "$mod" 2>/dev/null | grep -q "sig_id:" || echo "$mod"; done)
if [[ -n "$unsigned_mods" ]]; then
    save_evidence "unsigned-modules.txt" "echo '$unsigned_mods'"
    add_finding "MEDIUM" "Unsigned kernel modules loaded" "$(echo "$unsigned_mods" | wc -w) modules without signatures" "Verify legitimacy of unsigned kernel modules"
fi

# Mount points and filesystems
save_evidence "mounts.txt" "mount -l"
save_evidence "fstab.txt" "cat /etc/fstab 2>/dev/null"

# Environment variables (can contain leaked secrets)
save_evidence "environment.txt" "env | sort"
env_secrets=$(env | grep -iE 'password|secret|token|key|api_key|aws_' 2>/dev/null | wc -l)
if [[ "$env_secrets" -gt 0 ]]; then
    add_finding "HIGH" "Secrets in environment variables" "${env_secrets} potential secrets found in environment" "Remove secrets from environment variables — use vault/secret manager"
fi

log_pass "Volatile data collection complete"
fi


###############################################################################
# MODULE 2: PERSISTENCE MECHANISM HUNTING
###############################################################################
if $RUN_PERSISTENCE; then
section "MODULE 2: PERSISTENCE MECHANISM HUNTING"

# Cron jobs — all users
save_evidence "cron-system.txt" "cat /etc/crontab 2>/dev/null; ls -la /etc/cron.*/ 2>/dev/null; cat /etc/cron.d/* 2>/dev/null"
save_evidence "cron-users.txt" "for user in \$(cut -f1 -d: /etc/passwd); do echo \"=== \$user ===\"; crontab -l -u \$user 2>/dev/null || echo 'none'; done"

# Detect suspicious cron entries
cron_suspicious=$(cat /etc/crontab /etc/cron.d/* 2>/dev/null; for u in $(cut -f1 -d: /etc/passwd); do crontab -l -u "$u" 2>/dev/null; done)
if echo "$cron_suspicious" | grep -qiE 'curl|wget|nc |ncat|python.*-c|bash.*-i|/dev/tcp|base64|eval'; then
    add_finding "CRITICAL" "Suspicious cron job detected" "Cron entry contains download/reverse shell indicators" "Review all cron jobs for unauthorized entries"
fi

# Systemd services and timers
save_evidence "systemd-services.txt" "systemctl list-units --type=service --all --no-pager 2>/dev/null"
save_evidence "systemd-timers.txt" "systemctl list-timers --all --no-pager 2>/dev/null"
save_evidence "systemd-user-services.txt" "find /etc/systemd /run/systemd /usr/lib/systemd ~/.config/systemd -name '*.service' -o -name '*.timer' 2>/dev/null | xargs ls -la 2>/dev/null"

# Recently modified service files
recent_services=$(find /etc/systemd/system /usr/lib/systemd/system -name "*.service" -mtime -7 2>/dev/null)
if [[ -n "$recent_services" ]]; then
    save_evidence "recent-services.txt" "echo '$recent_services'"
    add_finding "MEDIUM" "Recently modified systemd services" "Service files modified in last 7 days" "Verify recently modified service files are authorized changes"
fi

# Init scripts
save_evidence "initd-scripts.txt" "ls -la /etc/init.d/ 2>/dev/null"
save_evidence "rc-local.txt" "cat /etc/rc.local 2>/dev/null"
if [[ -f /etc/rc.local ]] && grep -qvE '^\s*#|^\s*$|exit 0' /etc/rc.local 2>/dev/null; then
    add_finding "HIGH" "Active rc.local commands" "Commands found in /etc/rc.local" "Review /etc/rc.local for unauthorized persistence"
fi

# Shell profile persistence
save_evidence "shell-profiles.txt" "cat /etc/profile /etc/bash.bashrc /etc/environment 2>/dev/null; for h in /home/*/ /root/; do echo \"=== \$h ===\"; cat \${h}.bashrc \${h}.bash_profile \${h}.profile \${h}.bash_login \${h}.zshrc 2>/dev/null; done"
shell_backdoor=$(cat /etc/profile /etc/bash.bashrc /home/*/.bashrc /home/*/.bash_profile /root/.bashrc /root/.bash_profile 2>/dev/null | grep -iE 'curl|wget|nc |python.*-c|bash.*-i|/dev/tcp|base64.*decode|eval')
if [[ -n "$shell_backdoor" ]]; then
    add_finding "CRITICAL" "Backdoor in shell profile" "Shell startup files contain suspicious commands" "Inspect shell profiles for unauthorized code injection"
fi

# SSH authorized_keys
save_evidence "ssh-authorized-keys.txt" "find / -name 'authorized_keys' -o -name 'authorized_keys2' 2>/dev/null | xargs cat 2>/dev/null"
ssh_key_count=$(find / -name "authorized_keys" 2>/dev/null | xargs cat 2>/dev/null | grep -c "ssh-" || echo "0")
log_data "SSH authorized_keys: ${ssh_key_count} keys found"

# SSH config
save_evidence "sshd-config.txt" "cat /etc/ssh/sshd_config 2>/dev/null"
if grep -q "PermitRootLogin yes" /etc/ssh/sshd_config 2>/dev/null; then
    add_finding "HIGH" "SSH root login enabled" "PermitRootLogin is set to yes" "Set PermitRootLogin to no or prohibit-password"
fi

# LD_PRELOAD hijacking
save_evidence "ld-preload.txt" "cat /etc/ld.so.preload 2>/dev/null; echo '---'; env | grep LD_PRELOAD"
if [[ -s /etc/ld.so.preload ]]; then
    add_finding "CRITICAL" "LD_PRELOAD library injection" "$(cat /etc/ld.so.preload)" "Investigate /etc/ld.so.preload — common rootkit technique"
fi

# At jobs
save_evidence "at-jobs.txt" "atq 2>/dev/null; ls -la /var/spool/at/ 2>/dev/null"

log_pass "Persistence hunting complete"
fi


###############################################################################
# MODULE 3: MALWARE & WEBSHELL DETECTION
###############################################################################
if $RUN_MALWARE; then
section "MODULE 3: MALWARE & WEBSHELL DETECTION"

# Known malware file paths
MALWARE_PATHS=(
    "/tmp/.ice-unix" "/tmp/.X11-unix/.*" "/dev/shm/.??*"
    "/var/tmp/.??*" "/tmp/.??*" "/usr/lib/.??*"
    "/opt/.??*" "/var/run/.??*"
)
for mp in "${MALWARE_PATHS[@]}"; do
    found=$(find $(dirname "$mp") -name "$(basename "$mp")" -type f 2>/dev/null | head -5)
    if [[ -n "$found" ]]; then
        save_evidence "hidden-files-${RANDOM}.txt" "echo '$found'; ls -la $found 2>/dev/null; file $found 2>/dev/null"
        add_finding "HIGH" "Hidden files in suspicious location" "$found" "Investigate hidden files in /tmp, /dev/shm, /var/tmp"
    fi
done

# World-writable executables
save_evidence "world-writable-exec.txt" "find / -type f -perm -0002 -executable 2>/dev/null | head -100"
ww_exec=$(find / -type f -perm -0002 -executable 2>/dev/null | wc -l)
if [[ "$ww_exec" -gt 0 ]]; then
    add_finding "MEDIUM" "World-writable executables" "${ww_exec} world-writable executable files found" "Review and fix permissions on world-writable executables"
fi

# SUID/SGID binaries (potential privilege escalation)
save_evidence "suid-binaries.txt" "find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -la {} \; 2>/dev/null"
unusual_suid=$(find / -type f -perm -4000 2>/dev/null | grep -vE '/usr/bin/|/usr/sbin/|/usr/lib|/bin/' | head -20)
if [[ -n "$unusual_suid" ]]; then
    add_finding "HIGH" "Unusual SUID binaries" "SUID binaries found outside standard paths" "Review SUID binaries for potential privilege escalation vectors"
fi

# Webshell detection
WEBSHELL_SIGS='eval\s*\(\s*base64_decode|eval\s*\(\s*\$_|system\s*\(\s*\$_|exec\s*\(\s*\$_|passthru|shell_exec|proc_open|popen\s*\(|assert\s*\(\s*\$_|preg_replace.*\/e|<?php.*\$_GET.*eval|<?php.*\$_POST.*system|c99shell|r57shell|WSO\s|b374k|FilesMan|AnonymousFox'
WEB_DIRS=("/var/www" "/srv/www" "/var/html" "/usr/share/nginx" "/opt/www" "/home/*/public_html")
webshell_count=0
for wd in "${WEB_DIRS[@]}"; do
    if [[ -d "$wd" ]] || ls -d $wd 2>/dev/null | head -1 >/dev/null 2>&1; then
        found=$(grep -rlE "$WEBSHELL_SIGS" $wd 2>/dev/null | head -20)
        if [[ -n "$found" ]]; then
            save_evidence "webshells-${RANDOM}.txt" "echo '$found'; echo '---'; for f in $found; do echo \"=== \$f ===\"; head -5 \"\$f\" 2>/dev/null; echo; done"
            webshell_count=$((webshell_count + $(echo "$found" | wc -l)))
        fi
    fi
done
if [[ "$webshell_count" -gt 0 ]]; then
    add_finding "CRITICAL" "Potential webshells detected" "${webshell_count} files match webshell signatures" "Quarantine and analyze detected webshell files immediately"
else
    log_pass "No webshell signatures detected in web directories"
fi

# Crypto miner detection
save_evidence "crypto-miners.txt" "ps aux | grep -iE 'xmrig|minerd|cpuminer|stratum|nicehash|minergate|coinhive|cryptonight' | grep -v grep"
if ps aux | grep -qiE 'xmrig|minerd|cpuminer|stratum|cryptonight' 2>/dev/null | grep -qv grep; then
    add_finding "CRITICAL" "Crypto miner process detected" "Active cryptocurrency mining process found" "Kill the mining process and investigate how it was deployed"
fi

# Reverse shell detection
save_evidence "reverse-shells.txt" "ps aux | grep -iE 'bash -i|/dev/tcp|nc -e|ncat -e|python.*socket|perl.*socket|ruby.*socket|socat' | grep -v grep"
if ps aux | grep -iE 'bash.*-i.*>.*&|/dev/tcp|nc.*-e|ncat.*-e' 2>/dev/null | grep -qv grep; then
    add_finding "CRITICAL" "Potential reverse shell detected" "Active process matches reverse shell patterns" "Investigate and terminate suspected reverse shell immediately"
fi

# Rootkit detection — basic checks
save_evidence "rootkit-checks.txt" "
echo '=== /proc hidden process check ===';
for pid in /proc/[0-9]*/; do
    p=\$(basename \$pid);
    if ! ps -p \$p >/dev/null 2>&1; then
        echo \"Hidden PID: \$p\";
    fi;
done;
echo '=== Module hiding check ===';
diff <(cat /proc/modules | awk '{print \$1}' | sort) <(lsmod | awk 'NR>1{print \$1}' | sort) 2>/dev/null || true;
echo '=== Suspicious /proc entries ===';
ls -la /proc/*/exe 2>/dev/null | grep '(deleted)' | head -20;
"

# Files modified in last 24 hours in system directories
save_evidence "recent-system-changes.txt" "find /usr/bin /usr/sbin /bin /sbin /usr/lib -mtime -1 -type f 2>/dev/null"
recent_bin=$(find /usr/bin /usr/sbin /bin /sbin -mtime -1 -type f 2>/dev/null | wc -l)
if [[ "$recent_bin" -gt 0 ]]; then
    add_finding "HIGH" "Recently modified system binaries" "${recent_bin} system binaries modified in last 24 hours" "Verify integrity of recently modified binaries — possible trojanization"
fi

# Package integrity check
if command -v rpm &>/dev/null; then
    save_evidence "rpm-verify.txt" "rpm -Va 2>/dev/null | head -200"
    log_data "RPM verification captured"
elif command -v dpkg &>/dev/null; then
    save_evidence "dpkg-verify.txt" "dpkg --verify 2>/dev/null | head -200"
    log_data "DPKG verification captured"
fi

log_pass "Malware detection complete"
fi


###############################################################################
# MODULE 4: USER & AUTHENTICATION ANALYSIS
###############################################################################
if $RUN_USERS; then
section "MODULE 4: USER & AUTHENTICATION ANALYSIS"

save_evidence "passwd.txt" "cat /etc/passwd"
save_evidence "group.txt" "cat /etc/group"
save_evidence "shadow-perms.txt" "ls -la /etc/shadow /etc/gshadow 2>/dev/null"

# UID 0 accounts (should only be root)
uid0=$(awk -F: '$3==0{print $1}' /etc/passwd)
uid0_count=$(echo "$uid0" | wc -w)
if [[ "$uid0_count" -gt 1 ]]; then
    add_finding "CRITICAL" "Multiple UID 0 accounts" "UID 0 accounts: ${uid0}" "Only root should have UID 0 — investigate additional accounts"
fi

# Users with login shells
save_evidence "login-shells.txt" "grep -vE '/nologin|/false|/sync|/shutdown|/halt' /etc/passwd"
login_users=$(grep -vcE '/nologin|/false|/sync|/shutdown|/halt' /etc/passwd)
log_data "Users with login shells: ${login_users}"

# Accounts with no password
no_pass=$(awk -F: '($2=="" || $2=="!"){print $1}' /etc/shadow 2>/dev/null)
if [[ -n "$no_pass" ]]; then
    add_finding "HIGH" "Accounts with no/empty password" "${no_pass}" "Set strong passwords or lock passwordless accounts"
fi

# Sudoers
save_evidence "sudoers.txt" "cat /etc/sudoers 2>/dev/null; cat /etc/sudoers.d/* 2>/dev/null"
nopasswd=$(grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v "^#")
if [[ -n "$nopasswd" ]]; then
    add_finding "MEDIUM" "NOPASSWD sudo entries" "$(echo "$nopasswd" | wc -l) NOPASSWD rules found" "Review NOPASSWD sudo entries for least-privilege compliance"
fi

# Login history
save_evidence "last-logins.txt" "last -50 2>/dev/null"
save_evidence "lastb-failed.txt" "lastb -50 2>/dev/null"
save_evidence "wtmp-logins.txt" "last -f /var/log/wtmp 2>/dev/null | head -100"
save_evidence "currently-logged.txt" "w; echo '---'; who"

failed_logins=$(lastb 2>/dev/null | grep -vc "^$" || echo "0")
if [[ "$failed_logins" -gt 50 ]]; then
    add_finding "HIGH" "High failed login count" "${failed_logins} failed login attempts recorded" "Investigate brute-force attempts — consider account lockout policy"
fi

# SSH login activity
save_evidence "auth-log.txt" "grep -E 'sshd|sudo|su:' /var/log/auth.log /var/log/secure 2>/dev/null | tail -500"
ssh_accepted=$(grep -c "Accepted" /var/log/auth.log /var/log/secure 2>/dev/null || echo "0")
ssh_failed=$(grep -c "Failed" /var/log/auth.log /var/log/secure 2>/dev/null || echo "0")
log_data "SSH logins — Accepted: ${ssh_accepted}, Failed: ${ssh_failed}"

# Recently created users
save_evidence "recent-users.txt" "grep -E 'useradd|adduser|new user' /var/log/auth.log /var/log/secure 2>/dev/null | tail -20"

log_pass "User analysis complete"
fi


###############################################################################
# MODULE 5: NETWORK FORENSICS
###############################################################################
if $RUN_NETWORK; then
section "MODULE 5: NETWORK FORENSICS"

# Active connections
save_evidence "netstat-all.txt" "ss -tulnap 2>/dev/null || netstat -tulnap 2>/dev/null"
save_evidence "netstat-established.txt" "ss -tnap state established 2>/dev/null"

# Listening services
listeners=$(ss -tulnp 2>/dev/null | grep LISTEN | wc -l)
log_data "Listening services: ${listeners}"

# Suspicious outbound connections
save_evidence "outbound-connections.txt" "ss -tnap state established 2>/dev/null | awk '{print \$5}' | sort -u"
sus_ports=$(ss -tnap state established 2>/dev/null | grep -E ':4444|:5555|:6666|:1337|:31337|:8888|:9999' | head -10)
if [[ -n "$sus_ports" ]]; then
    add_finding "CRITICAL" "Suspicious outbound connection" "Connections to known C2 ports detected" "Investigate connections to ports 4444/5555/6666/1337/31337"
fi

# DNS configuration
save_evidence "dns-config.txt" "cat /etc/resolv.conf 2>/dev/null; echo '---'; cat /etc/hosts"
rogue_dns=$(grep "nameserver" /etc/resolv.conf 2>/dev/null | grep -vE '127\.|8\.8\.|1\.1\.|9\.9\.' | head -5)
if [[ -n "$rogue_dns" ]]; then
    add_finding "MEDIUM" "Non-standard DNS servers" "${rogue_dns}" "Verify DNS server configuration is authorized"
fi

# ARP table
save_evidence "arp-table.txt" "ip neigh show 2>/dev/null || arp -an 2>/dev/null"

# Routing
save_evidence "routes.txt" "ip route show 2>/dev/null || route -n 2>/dev/null"

# Firewall rules
save_evidence "iptables.txt" "iptables -L -n -v 2>/dev/null"
save_evidence "nftables.txt" "nft list ruleset 2>/dev/null"
if ! iptables -L -n 2>/dev/null | grep -q "DROP\|REJECT" && ! nft list ruleset 2>/dev/null | grep -q "drop\|reject"; then
    add_finding "HIGH" "No firewall rules active" "No DROP/REJECT rules found in iptables or nftables" "Configure host-based firewall with deny-by-default policy"
fi

# Network interfaces (promiscuous mode check)
save_evidence "interfaces.txt" "ip addr show 2>/dev/null"
promisc=$(ip link show 2>/dev/null | grep "PROMISC")
if [[ -n "$promisc" ]]; then
    add_finding "HIGH" "Interface in promiscuous mode" "$promisc" "Investigate promiscuous mode — possible packet sniffing"
fi

log_pass "Network forensics complete"
fi


###############################################################################
# MODULE 6: LOG ANALYSIS
###############################################################################
if $RUN_LOGS; then
section "MODULE 6: LOG ANALYSIS"

# Collect key logs
for logfile in /var/log/syslog /var/log/messages /var/log/auth.log /var/log/secure /var/log/kern.log /var/log/dmesg /var/log/cron /var/log/maillog /var/log/httpd/access_log /var/log/httpd/error_log /var/log/nginx/access.log /var/log/nginx/error.log /var/log/apache2/access.log /var/log/apache2/error.log; do
    if [[ -f "$logfile" ]]; then
        fname=$(echo "$logfile" | tr '/' '-' | sed 's/^-//')
        save_evidence "log-${fname}.txt" "tail -2000 '$logfile'"
    fi
done

# Log tampering detection
save_evidence "log-gaps.txt" "
for lf in /var/log/syslog /var/log/messages /var/log/auth.log /var/log/secure; do
    if [[ -f \"\$lf\" ]]; then
        echo \"=== \$lf ===\";
        echo \"Size: \$(wc -c < \"\$lf\") bytes\";
        echo \"Lines: \$(wc -l < \"\$lf\")\";
        echo \"First: \$(head -1 \"\$lf\")\";
        echo \"Last: \$(tail -1 \"\$lf\")\";
    fi;
done"

# Empty or truncated logs
for lf in /var/log/syslog /var/log/messages /var/log/auth.log /var/log/secure; do
    if [[ -f "$lf" ]] && [[ ! -s "$lf" ]]; then
        add_finding "CRITICAL" "Empty log file" "${lf} is empty — possible log tampering" "Investigate log deletion — restore from backup or SIEM"
    fi
done

# Audit log
save_evidence "audit-log.txt" "ausearch -m execve -ts today 2>/dev/null | tail -500 || tail -500 /var/log/audit/audit.log 2>/dev/null"

# Brute force indicators
bf_count=$(grep -cE "Failed password|authentication failure" /var/log/auth.log /var/log/secure 2>/dev/null || echo "0")
if [[ "$bf_count" -gt 100 ]]; then
    add_finding "HIGH" "Brute force indicators in logs" "${bf_count} authentication failures detected" "Implement fail2ban or account lockout — investigate source IPs"
fi

# Privilege escalation attempts
priv_esc=$(grep -cE "sudo.*FAILED|COMMAND.*sudo|su\[.*authentication failure" /var/log/auth.log /var/log/secure 2>/dev/null || echo "0")
if [[ "$priv_esc" -gt 20 ]]; then
    add_finding "HIGH" "Privilege escalation attempts" "${priv_esc} sudo/su failures detected" "Review privilege escalation attempts for potential lateral movement"
fi

log_pass "Log analysis complete"
fi


###############################################################################
# MODULE 7: IOC EXTRACTION
###############################################################################
if $RUN_IOC; then
section "MODULE 7: IOC EXTRACTION"

# Extract unique external IPs from connections
save_evidence "ioc-ips.txt" "ss -tnap state established 2>/dev/null | awk '{print \$5}' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | grep -vE '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.)' | sort -u"
ext_ips=$(ss -tnap state established 2>/dev/null | awk '{print $5}' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | grep -vE '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.)' | sort -u | wc -l)
log_data "External IPs (active connections): ${ext_ips}"

# Extract IPs from logs
save_evidence "ioc-ips-logs.txt" "grep -rohE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages 2>/dev/null | grep -vE '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.)' | sort | uniq -c | sort -rn | head -50"

# Extract domains from logs
save_evidence "ioc-domains.txt" "grep -rohE '[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}' /var/log/syslog /var/log/messages 2>/dev/null | sort -u | head -200"

# Extract URLs
save_evidence "ioc-urls.txt" "grep -rohE 'https?://[^ \"<>]+' /var/log/syslog /var/log/messages /var/log/auth.log /tmp/* /var/tmp/* 2>/dev/null | sort -u | head -100"

# File hashes of suspicious items
save_evidence "ioc-hashes.txt" "
echo '=== Recently modified binaries ===';
find /usr/bin /usr/sbin /bin /sbin -mtime -3 -type f 2>/dev/null | xargs sha256sum 2>/dev/null;
echo '=== Files in /tmp ===';
find /tmp -type f -executable 2>/dev/null | xargs sha256sum 2>/dev/null;
echo '=== Files in /dev/shm ===';
find /dev/shm -type f 2>/dev/null | xargs sha256sum 2>/dev/null;
"

# Suspicious command history
save_evidence "ioc-history.txt" "
for h in /root/.bash_history /home/*/.bash_history /root/.zsh_history /home/*/.zsh_history; do
    if [[ -f \"\$h\" ]]; then
        echo \"=== \$h ===\";
        grep -iE 'wget|curl|nc |ncat|python.*http|base64|eval|chmod.*777|/dev/tcp|reverse|shell|passwd|shadow|ssh-keygen|authorized_keys|iptables.*-F|history.*-c' \"\$h\" 2>/dev/null | tail -30;
    fi;
done"
hist_sus=$(cat /root/.bash_history /home/*/.bash_history 2>/dev/null | grep -ciE 'wget.*\|.*sh|curl.*\|.*bash|base64.*decode|nc.*-e|/dev/tcp' || echo "0")
if [[ "$hist_sus" -gt 0 ]]; then
    add_finding "HIGH" "Suspicious commands in shell history" "${hist_sus} suspicious command patterns found" "Review shell history for evidence of compromise"
fi

log_pass "IOC extraction complete"
fi


###############################################################################
# MODULE 8: TIMELINE RECONSTRUCTION
###############################################################################
if $RUN_TIMELINE; then
section "MODULE 8: TIMELINE RECONSTRUCTION"

save_evidence "timeline-files.txt" "
echo 'Recent file modifications across system (last 72 hours):';
find / -xdev -type f -mtime -3 -printf '%T+ %p\n' 2>/dev/null | sort -r | head -500"

save_evidence "timeline-auth.txt" "
echo 'Authentication events timeline:';
grep -hE 'Accepted|Failed|session opened|session closed|sudo:' /var/log/auth.log /var/log/secure 2>/dev/null | tail -200"

save_evidence "timeline-packages.txt" "
echo 'Package installation history:';
if [[ -f /var/log/dpkg.log ]]; then grep 'install ' /var/log/dpkg.log | tail -50;
elif [[ -f /var/log/yum.log ]]; then tail -50 /var/log/yum.log;
elif command -v rpm &>/dev/null; then rpm -qa --last | head -50;
fi"

save_evidence "timeline-logins.txt" "last -50 2>/dev/null"

log_pass "Timeline reconstruction complete"
fi


###############################################################################
# REPORT GENERATION
###############################################################################
if ! $NO_REPORT; then
section "GENERATING FORENSIC REPORT"

# Calculate score
total_checks=$((FINDING_COUNT + 20))
score=$((100 - (CRITICAL_COUNT * 15) - (HIGH_COUNT * 8) - (MEDIUM_COUNT * 3) - (LOW_COUNT * 1)))
[[ $score -lt 0 ]] && score=0

score_color="#2ed573"
[[ $score -lt 80 ]] && score_color="#f0a500"
[[ $score -lt 60 ]] && score_color="#ff6348"
[[ $score -lt 40 ]] && score_color="#ff4757"

# Generate HTML findings
findings_html=""
for f in "${FINDINGS[@]}"; do
    IFS='|' read -r sev title detail remed <<< "$f"
    sev_color="#999"
    case "$sev" in
        CRITICAL) sev_color="#ff4757" ;; HIGH) sev_color="#ff6348" ;;
        MEDIUM) sev_color="#f0a500" ;; LOW) sev_color="#2ed573" ;; INFO) sev_color="#00d4ff" ;;
    esac
    findings_html+="<div style='background:#111a2a;border:1px solid #1a2a40;border-left:3px solid ${sev_color};border-radius:6px;padding:12px;margin:8px 0'>"
    findings_html+="<div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:6px'>"
    findings_html+="<strong style='color:#c8d6e5'>${title}</strong>"
    findings_html+="<span style='background:${sev_color}15;color:${sev_color};border:1px solid ${sev_color}30;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700'>${sev}</span></div>"
    findings_html+="<div style='color:#7a8ea0;font-size:13px'>${detail}</div>"
    [[ -n "$remed" ]] && findings_html+="<div style='color:#4a5d70;font-size:12px;margin-top:6px;border-top:1px solid #1a2a40;padding-top:6px'>Remediation: ${remed}</div>"
    findings_html+="</div>"
done

# Evidence file list
evidence_html=""
for ef in "${EVIDENCE_DIR}"/*; do
    [[ -f "$ef" ]] && evidence_html+="<div style='padding:4px 0;font-size:12px;color:#7a8ea0;border-bottom:1px solid #1a2a40'>$(basename "$ef") — $(wc -c < "$ef") bytes</div>"
done

cat > "$REPORT_FILE" << REPORTEOF
<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>ShadowPulse Forensic Report — ${HOSTNAME}</title>
<style>
body{font-family:'JetBrains Mono',Consolas,monospace;background:#080c14;color:#c8d6e5;padding:24px;max-width:960px;margin:0 auto;font-size:13px}
h1{color:#00d4ff;font-size:1.5rem;margin-bottom:4px}
h2{color:#00d4ff;border-bottom:1px solid #1a2a40;padding-bottom:6px;margin-top:24px;font-size:1rem}
.stat{display:inline-block;padding:8px 16px;margin:4px;border:1px solid #1a2a40;border-radius:6px;background:#111a2a}
.meta{color:#4a5d70;font-size:12px;line-height:1.8}
</style></head>
<body>
<h1>ShadowPulse Forensic Report</h1>
<p style="color:#7a8ea0;margin-bottom:16px">Linux Threat Hunting &amp; Incident Response</p>
<div class="meta">
Hostname: ${HOSTNAME}<br>
Kernel: $(uname -r)<br>
Date: ${DATE_ISO}<br>
Investigator: $(whoami)<br>
Modules: ${MODULE_COUNT}<br>
Case: ${CASE_DIR}
</div>

<h2>Executive Summary</h2>
<div class="stat" style="color:${score_color};font-size:1.3em;font-weight:700">Score: ${score}%</div>
<div class="stat" style="color:#ff4757">Critical: ${CRITICAL_COUNT}</div>
<div class="stat" style="color:#ff6348">High: ${HIGH_COUNT}</div>
<div class="stat" style="color:#f0a500">Medium: ${MEDIUM_COUNT}</div>
<div class="stat" style="color:#2ed573">Low: ${LOW_COUNT}</div>
<div class="stat" style="color:#00d4ff">Info: ${INFO_COUNT}</div>
<div class="stat">Total: ${FINDING_COUNT}</div>

<h2>Findings</h2>
${findings_html}

<h2>Evidence Files</h2>
${evidence_html}

<h2>Chain of Custody</h2>
<p style="color:#4a5d70;font-size:12px">SHA-256 hashes of all evidence files are stored in:<br>${HASHES_FILE}</p>

<p style="margin-top:24px;color:#4a5d70;font-size:11px">ShadowPulse v${VERSION} — github.com/SiteQ8/ShadowPulse — Made in Kuwait</p>
</body></html>
REPORTEOF

sha256sum "$REPORT_FILE" >> "$HASHES_FILE" 2>/dev/null
log_pass "Report generated: ${REPORT_FILE}"
fi


###############################################################################
# SUMMARY
###############################################################################
echo ""
echo -e "${BOLD}════════════════════════════════════════════════════════════${N}"
echo -e "  ${W}ShadowPulse Investigation Complete${N}"
echo -e "════════════════════════════════════════════════════════════"
echo -e "  Hostname:      ${HOSTNAME}"
echo -e "  Modules:       ${MODULE_COUNT}"
echo -e "  Findings:      ${FINDING_COUNT}"
echo -e "    Critical:    ${R}${CRITICAL_COUNT}${N}"
echo -e "    High:        ${R}${HIGH_COUNT}${N}"
echo -e "    Medium:      ${Y}${MEDIUM_COUNT}${N}"
echo -e "    Low:         ${G}${LOW_COUNT}${N}"
echo -e "    Info:        ${C}${INFO_COUNT}${N}"
echo -e "  Evidence:      ${EVIDENCE_DIR}/"
echo -e "  Report:        ${REPORT_FILE}"
echo -e "  Chain:         ${HASHES_FILE}"
echo -e "════════════════════════════════════════════════════════════"
echo ""
