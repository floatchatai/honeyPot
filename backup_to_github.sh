#!/bin/bash
# Sync the system-side pieces into the repo, commit everything that changed, push to GitHub.
# Usage: /opt/voip/backup_to_github.sh            (run as root; safe to run from cron)
set -u
cd /opt/voip || exit 1
mkdir -p system/freeswitch system/systemd system/cron system/sbin system/root
rsync -a --delete /usr/local/freeswitch/conf/    system/freeswitch/conf/   2>/dev/null
rsync -a --delete /usr/local/freeswitch/scripts/ system/freeswitch/scripts/ 2>/dev/null
cp -p /etc/systemd/system/voip-*.service system/systemd/ 2>/dev/null; cp -rp /etc/systemd/system/voip-frontend.service.d system/systemd/ 2>/dev/null
cp -p /etc/systemd/system/freeswitch.service /etc/systemd/system/fs-watchdog.* system/systemd/ 2>/dev/null; cp -rp /etc/systemd/system/freeswitch.service.d system/systemd/ 2>/dev/null
cp -p /etc/cron.d/voip-* system/cron/ 2>/dev/null
cp -p /usr/local/sbin/update_voip_* /usr/local/sbin/voip_retention /usr/local/bin/fs_watchdog.sh system/sbin/ 2>/dev/null
cp -p /root/opt.sh /root/gatecheck.sh /root/moddiag.sh system/root/ 2>/dev/null
# FreeSWITCH event-socket password must not go to GitHub
sed -i -E 's/(name="password" value=")[^"]*(")/\1REDACTED\2/' system/freeswitch/conf/autoload_configs/event_socket.conf.xml 2>/dev/null
git add -A
if git diff --cached --quiet; then echo "backup: nothing changed"; exit 0; fi
git commit -q -m "Backup $(date '+%Y-%m-%d %H:%M %Z') from $(hostname)" && echo "backup: committed"
if git remote get-url origin >/dev/null 2>&1; then git push -q origin HEAD:main && echo "backup: pushed to GitHub" || { echo "backup: push failed"; exit 1; }; else echo "backup: no 'origin' remote yet, commit kept locally"; fi
