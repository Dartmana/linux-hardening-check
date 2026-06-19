#!/bin/bash
# hardening_check.sh - audits your linux system security config
# checks ssh settings, firewall, open ports, file permissions, and users
# run with sudo for full results

RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BOLD='\033[1m'
RESET='\033[0m'

pass=0
warn=0
fail=0

passed()  { echo -e "  ${GREEN}[PASS]${RESET} $1"; ((pass++)); }
failed()  { echo -e "  ${RED}[FAIL]${RESET} $1"; ((fail++)); }
warning() { echo -e "  ${YELLOW}[WARN]${RESET} $1"; ((warn++)); }
header()  { echo -e "\n${BOLD}$1${RESET}\n  $(printf '─%.0s' {1..50})"; }


header "SSH Configuration"

sshd_config="/etc/ssh/sshd_config"

if [ -f "$sshd_config" ]; then
    # check if root login is disabled
    if grep -qiE "^\s*PermitRootLogin\s+no" "$sshd_config"; then
        passed "root login disabled"
    else
        failed "root login is not explicitly disabled (PermitRootLogin)"
    fi

    # check if password auth is off
    if grep -qiE "^\s*PasswordAuthentication\s+no" "$sshd_config"; then
        passed "password authentication disabled (keys only)"
    else
        warning "password authentication is enabled — consider switching to keys only"
    fi

    # check if empty passwords are blocked
    if grep -qiE "^\s*PermitEmptyPasswords\s+no" "$sshd_config"; then
        passed "empty passwords blocked"
    else
        warning "PermitEmptyPasswords not explicitly set to no"
    fi

    # check ssh port
    ssh_port=$(grep -iE "^\s*Port\s+" "$sshd_config" | awk '{print $2}' | head -1)
    if [ -z "$ssh_port" ] || [ "$ssh_port" = "22" ]; then
        warning "SSH running on default port 22 — consider changing it"
    else
        passed "SSH running on non-default port $ssh_port"
    fi

    # check max auth tries
    max_tries=$(grep -iE "^\s*MaxAuthTries\s+" "$sshd_config" | awk '{print $2}' | head -1)
    if [ -n "$max_tries" ] && [ "$max_tries" -le 4 ]; then
        passed "MaxAuthTries set to $max_tries"
    else
        warning "MaxAuthTries not set or too high — recommend setting to 3 or 4"
    fi
else
    warning "sshd_config not found — is SSH installed?"
fi


header "Firewall"

if command -v ufw &>/dev/null; then
    ufw_status=$(ufw status 2>/dev/null | head -1)
    if echo "$ufw_status" | grep -qi "active"; then
        passed "ufw firewall is active"

        # check if default incoming is deny
        if ufw status verbose 2>/dev/null | grep -qi "Default: deny (incoming)"; then
            passed "default incoming policy is deny"
        else
            warning "default incoming policy may not be set to deny"
        fi
    else
        failed "ufw is installed but not active — run: sudo ufw enable"
    fi
else
    warning "ufw not found — no firewall detected"
fi


header "Open Ports"

if command -v ss &>/dev/null; then
    # find ports listening on all interfaces (0.0.0.0 or ::)
    open=$(ss -tuln 2>/dev/null | grep -E "0\.0\.0\.0|::" | awk '{print $5}' | grep -oE '[0-9]+$' | sort -un)
    count=$(echo "$open" | grep -c .)
    if [ "$count" -le 5 ]; then
        passed "only $count port(s) listening externally: $(echo $open | tr '\n' ' ')"
    else
        warning "$count ports listening externally — review with: ss -tuln"
        echo "         ports: $(echo $open | tr '\n' ' ')"
    fi
fi


header "File Permissions"

# check /etc/passwd is not world writable
if [ "$(stat -c %a /etc/passwd)" = "644" ]; then
    passed "/etc/passwd permissions are 644"
else
    failed "/etc/passwd has unusual permissions: $(stat -c %a /etc/passwd)"
fi

# check /etc/shadow is locked down
shadow_perms=$(stat -c %a /etc/shadow 2>/dev/null)
if [ "$shadow_perms" = "640" ] || [ "$shadow_perms" = "000" ] || [ "$shadow_perms" = "600" ]; then
    passed "/etc/shadow permissions look good ($shadow_perms)"
else
    failed "/etc/shadow permissions may be too open: $shadow_perms"
fi

# check for world writable files in /etc
ww_files=$(find /etc -maxdepth 1 -perm -o+w 2>/dev/null | wc -l)
if [ "$ww_files" -eq 0 ]; then
    passed "no world-writable files in /etc"
else
    failed "$ww_files world-writable file(s) found in /etc"
fi

# check /tmp sticky bit
if [ "$(stat -c %a /tmp)" = "1777" ]; then
    passed "/tmp has sticky bit set (1777)"
else
    warning "/tmp sticky bit may not be set — current: $(stat -c %a /tmp)"
fi


header "Users & Accounts"

# find users with UID 0 other than root
uid0=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd)
if [ -z "$uid0" ]; then
    passed "no extra users with UID 0"
else
    failed "users with UID 0 (root privileges): $uid0"
fi

# check for accounts with no password
no_pass=$(sudo awk -F: '($2 == "" || $2 == "!") && $1 !~ /^(root|daemon|bin|sys|sync|games|man|lp|mail|news|uucp|proxy|www-data|backup|list|irc|gnats|nobody|systemd|messagebus|syslog|_apt|sshd)$/ {print $1}' /etc/shadow 2>/dev/null)
if [ -z "$no_pass" ]; then
    passed "no unlocked accounts with empty passwords"
else
    warning "accounts with no password set: $no_pass"
fi

# list users who can sudo
echo -e "  ${YELLOW}[INFO]${RESET} users in sudo group: $(getent group sudo | cut -d: -f4)"


header "System Updates"

if command -v apt &>/dev/null; then
    updates=$(apt list --upgradable 2>/dev/null | grep -c upgradable)
    if [ "$updates" -eq 0 ]; then
        passed "system is up to date"
    else
        warning "$updates package(s) have updates available — run: sudo apt upgrade"
    fi
fi


# summary
echo -e "\n${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "  ${GREEN}PASS: $pass${RESET}   ${YELLOW}WARN: $warn${RESET}   ${RED}FAIL: $fail${RESET}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n"
