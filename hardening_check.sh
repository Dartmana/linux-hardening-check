#!/bin/bash
# hardening_check.sh - checks some basic security stuff on linux
# run with: sudo bash hardening_check.sh

pass=0
fail=0
warn=0

# helper functions so i dont have to type the same echo every time
ok()   { echo "[PASS] $1"; pass=$((pass+1)); }
bad()  { echo "[FAIL] $1"; fail=$((fail+1)); }
maybe(){ echo "[WARN] $1"; warn=$((warn+1)); }

echo ""
echo "--- SSH Settings ---"

# check if root can log in over ssh
if grep -qi "PermitRootLogin no" /etc/ssh/sshd_config 2>/dev/null; then
    ok "root login over ssh is disabled"
else
    bad "root login over ssh is not disabled"
fi

# check if password login is off (keys only is more secure)
if grep -qi "PasswordAuthentication no" /etc/ssh/sshd_config 2>/dev/null; then
    ok "password auth is off, keys only"
else
    maybe "password auth is still on"
fi

# check if ssh is on a weird port (less likely to get scanned)
port=$(grep -i "^Port" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
if [ "$port" != "" ] && [ "$port" != "22" ]; then
    ok "ssh is on a non-default port ($port)"
else
    maybe "ssh is on the default port 22"
fi

echo ""
echo "--- Firewall ---"

# check if ufw is running
if ufw status 2>/dev/null | grep -q "active"; then
    ok "firewall (ufw) is active"
else
    bad "firewall is not active"
fi

echo ""
echo "--- File Permissions ---"

# /etc/passwd should be readable by everyone but only writable by root
perms=$(stat -c %a /etc/passwd 2>/dev/null)
if [ "$perms" = "644" ]; then
    ok "/etc/passwd permissions are fine (644)"
else
    bad "/etc/passwd has wrong permissions: $perms"
fi

# /etc/shadow stores password hashes, should be locked down
perms=$(stat -c %a /etc/shadow 2>/dev/null)
if [ "$perms" = "640" ] || [ "$perms" = "600" ]; then
    ok "/etc/shadow permissions are fine ($perms)"
else
    bad "/etc/shadow permissions look off: $perms"
fi

echo ""
echo "--- User Accounts ---"

# check for any users with root-level access besides root itself
extra_roots=$(awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd)
if [ -z "$extra_roots" ]; then
    ok "no extra accounts with root uid"
else
    bad "found accounts with uid 0: $extra_roots"
fi

echo ""
echo "--- Open Ports ---"

# count how many ports are listening on all interfaces
open=$(ss -tuln 2>/dev/null | grep "0.0.0.0" | wc -l)
if [ "$open" -lt 10 ]; then
    ok "$open ports listening externally"
else
    maybe "$open ports open externally, might want to check"
fi

echo ""
echo "--- Summary ---"
echo "passed: $pass  failed: $fail  warnings: $warn"
echo ""
