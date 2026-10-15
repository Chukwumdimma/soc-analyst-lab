# Linux Log Cheat Sheet

Notes from the Linux Log Hunt vault and my own study.

## Where the logs are
| What | Ubuntu / Debian | CentOS / RHEL |
|---|---|---|
| Logins, SSH, sudo | `/var/log/auth.log` | `/var/log/secure` |
| General system messages | `/var/log/syslog` | `/var/log/messages` |
| Apache access log | `/var/log/apache2/access.log` | `/var/log/httpd/access_log` |
| Nginx access log | `/var/log/nginx/access.log` | `/var/log/nginx/access.log` |
| Cron activity | `/var/log/syslog` | `/var/log/cron` |
| auditd records | `/var/log/audit/audit.log` | `/var/log/audit/audit.log` |

## Commands
| Command | What it does |
|---|---|
| `last` | Shows past successful logins (reads `/var/log/wtmp`) |
| `lastb` | Shows failed logins (reads `/var/log/btmp`) |
| `journalctl -u sshd.service` | Shows systemd journal entries for one service |
| `grep "Failed password" /var/log/auth.log` | Finds failed SSH logins |

## Reading a log line
- **SSH failure:** `Failed password for invalid user admin from 203.0.113.45 port 49822`. "invalid user" means the account doesn't exist. The IP comes after `from`.
- **sudo:** `COMMAND=` shows the exact program and file. `/etc/shadow` holds password hashes, so reading it with sudo needs checking.
- **Apache or Nginx:** the request is in quotes (`GET /admin/login.php`), followed by the status code. 200 means the page was served, not that anyone logged in.

## Things I noticed
- A failed login for a username that doesn't exist, followed by a successful login from the same IP, is a pattern to investigate. It doesn't prove the account was compromised.
- A cron log shows when a job ran. The job itself is defined in a crontab file, so I need both before calling something persistence.
- The same log has a different name depending on the distribution family, so I check Ubuntu or RHEL first.
