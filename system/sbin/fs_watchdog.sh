#!/bin/bash
set -euo pipefail
FS_CLI="/usr/bin/fs_cli"
LOG_FILE="/var/log/fs_watchdog.log"
CPU_LIMIT=60.0
timestamp() { date '+%Y-%m-%d %H:%M:%S'; }

echo "[$(timestamp)] Watchdog run..." >> "$LOG_FILE"

if ! systemctl is-active --quiet freeswitch; then
  echo "[$(timestamp)] FAIL: FreeSWITCH not active -> restarting" >> "$LOG_FILE"
  systemctl restart freeswitch
  exit 0
fi

if [[ ! -x "$FS_CLI" ]]; then
  echo "[$(timestamp)] WARN: fs_cli not found ($FS_CLI). Only checking service state." >> "$LOG_FILE"
  exit 0
fi

MAX_SESSIONS="$("$FS_CLI" -x "fsctl max_sessions" 2>/dev/null | awk '{print $NF}' | head -n 1 || echo 0)"
CUR_SESSIONS="$("$FS_CLI" -x "show channels count" 2>/dev/null | tr -d '\r' | tail -n 1 || echo 0)"
CPU_LOAD="$(awk '{print $1}' /proc/loadavg)"

MAX_SESSIONS="${MAX_SESSIONS//[^0-9]/}"
CUR_SESSIONS="${CUR_SESSIONS//[^0-9]/}"
MAX_SESSIONS="${MAX_SESSIONS:-0}"
CUR_SESSIONS="${CUR_SESSIONS:-0}"

if (( MAX_SESSIONS > 0 )) && (( CUR_SESSIONS >= MAX_SESSIONS - 100 )); then
  echo "[$(timestamp)] WARN: Near max sessions ($CUR_SESSIONS/$MAX_SESSIONS) -> restarting" >> "$LOG_FILE"
  systemctl restart freeswitch
  exit 0
fi

if command -v bc >/dev/null 2>&1; then
  LOAD_INT=$(echo "$CPU_LOAD > $CPU_LIMIT" | bc -l)
  if (( LOAD_INT == 1 )); then
    echo "[$(timestamp)] WARN: High load ($CPU_LOAD) > $CPU_LIMIT -> restarting" >> "$LOG_FILE"
    systemctl restart freeswitch
    exit 0
  fi
else
  echo "[$(timestamp)] INFO: bc not installed; skipping CPU threshold check (load=$CPU_LOAD)" >> "$LOG_FILE"
fi

echo "[$(timestamp)] OK: Sessions=$CUR_SESSIONS Max=$MAX_SESSIONS Load=$CPU_LOAD" >> "$LOG_FILE"
