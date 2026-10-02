# VoIP HoneyPot panel – server backup

Backup of the panel code and configuration from the FreeSWITCH honeypot server.

- `app.py`, `voip_gate.py`, `voip_intel.py`, `assets/` – the panel
- `companies/` – companies, routing, gate lists, categories, pricing, audit log
- `system/` – copies of FreeSWITCH config/scripts, systemd units, cron jobs and helper scripts (synced by `backup_to_github.sh`)

Deliberately **not** in this repository: Azure keys and credentials, password hashes, call recordings, transcripts and
analyses, decision logs with phone numbers, vendored binaries, downloaded reputation datasets. See `.gitignore`.

Run `/opt/voip/backup_to_github.sh` to sync, commit and push.
