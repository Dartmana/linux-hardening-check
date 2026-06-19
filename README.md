# linux-hardening-check

A Bash script that audits your Linux system's security configuration and gives a pass/fail/warn report.

## What it checks

- SSH config (root login, password auth, port, max attempts)
- Firewall status (ufw)
- Open ports listening externally
- File permissions (/etc/passwd, /etc/shadow, /tmp)
- User accounts (UID 0, empty passwords, sudo users)
- Pending system updates

## Usage

```bash
chmod +x hardening_check.sh
sudo ./hardening_check.sh
```
