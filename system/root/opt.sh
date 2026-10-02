#!/bin/bash
# ------------------------------------------------------------------
# FreeSWITCH Optimization + systemd tuning (Auto-detect install type)
# Debian-first enhancements:
#   - Foreground FreeSWITCH under systemd (fixes restart loop)
#   - systemd watchdog timer (no cron)
#   - report-style logs, before/after
#   - --dry-run (audit only)
#   - --rollback <RUN_ID>
# ------------------------------------------------------------------

set -euo pipefail

LOG_FILE="/var/log/fs_optimize_report.log"
RUN_ID="$(date '+%Y%m%d_%H%M%S')"
HOST="$(hostname -f 2>/dev/null || hostname)"
SCRIPT_NAME="$(basename "$0")"
DRY_RUN=0
ROLLBACK_ID=""

timestamp() { date '+%Y-%m-%d %H:%M:%S'; }
log() { echo "[$(timestamp)] $*" | tee -a "$LOG_FILE"; }
section() {
  echo | tee -a "$LOG_FILE"
  echo "====================================================================" | tee -a "$LOG_FILE"
  echo "[$(timestamp)] $*" | tee -a "$LOG_FILE"
  echo "====================================================================" | tee -a "$LOG_FILE"
}
kv() { log " - $1: $2"; }

run_cmd() {
  if (( DRY_RUN == 1 )); then
    log "DRY-RUN: $*"
    return 0
  fi
  eval "$@"
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "This script must be run as root."
    exit 1
  fi
}

usage() {
  cat <<EOF
Usage:
  sudo ./$SCRIPT_NAME                # apply changes
  sudo ./$SCRIPT_NAME --dry-run      # audit only (no changes)
  sudo ./$SCRIPT_NAME --rollback ID  # restore backups from a prior run

Logs:
  $LOG_FILE
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dry-run) DRY_RUN=1; shift ;;
      --rollback) shift; ROLLBACK_ID="${1:-}"; [[ -z "$ROLLBACK_ID" ]] && exit 1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) echo "Unknown arg: $1"; usage; exit 1 ;;
    esac
  done
}

safe_backup() {
  local f="$1"
  if [[ -f "$f" ]]; then
    local b="${f}.bak_${RUN_ID}"
    if (( DRY_RUN == 1 )); then
      log "DRY-RUN: Would backup $f -> $b"
    else
      cp -a "$f" "$b"
      log "Backup created: $b"
    fi
  fi
}

rollback_file() {
  local target="$1"
  local backup="${target}.bak_${ROLLBACK_ID}"
  if [[ -f "$backup" ]]; then
    run_cmd "cp -a \"$backup\" \"$target\""
    log "ROLLED BACK: $target <- $backup"
  else
    log "ROLLBACK SKIP: backup not found for $target (expected: $backup)"
  fi
}

detect_bin() {
  local name="$1"
  local p=""
  p="$(command -v "$name" 2>/dev/null || true)"
  [[ -n "$p" && -x "$p" ]] && { echo "$p"; return 0; }
  return 1
}

detect_conf_file() {
  local candidates=(
    "/etc/freeswitch/autoload_configs/switch.conf.xml"
    "/usr/local/freeswitch/conf/autoload_configs/switch.conf.xml"
    "/opt/freeswitch/conf/autoload_configs/switch.conf.xml"
  )
  for c in "${candidates[@]}"; do [[ -f "$c" ]] && { echo "$c"; return 0; }; done
  local found=""
  found="$(find /etc /usr/local /opt /usr -maxdepth 6 -type f -name "switch.conf.xml" 2>/dev/null | head -n 1 || true)"
  [[ -n "$found" ]] && { echo "$found"; return 0; }
  return 1
}

list_fs_units() {
  # Show any unit names that contain 'freeswitch'
  systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -i "freeswitch" || true
}

detect_systemd_unit_exact() {
  local unit="$1"
  systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$unit"
}

get_current_param_value() {
  local file="$1"
  local param="$2"
  grep -oP "<param\s+name=\"$param\"\s+value=\"\K[^\"]+" "$file" 2>/dev/null | head -n 1 || true
}

set_or_insert_param() {
  local file="$1" param="$2" newval="$3"
  local oldval; oldval="$(get_current_param_value "$file" "$param")"
  if grep -q "<param name=\"$param\"" "$file"; then
    if (( DRY_RUN == 1 )); then
      log "DRY-RUN: Would change $param: '${oldval:-<empty>}' -> '$newval' in $file"
      return 0
    fi
    sed -i -E "s#(<param name=\"$param\" value=\")[^\"]*(\"/>)#\1${newval}\2#g" "$file"
    log "CHANGED: $param: '${oldval:-<empty>}' -> '$newval'"
  else
    if (( DRY_RUN == 1 )); then
      log "DRY-RUN: Would add $param='$newval' into $file"
      return 0
    fi
    if grep -q "</settings>" "$file"; then
      sed -i -E "s#</settings>#    <param name=\"$param\" value=\"$newval\"/>\n</settings>#g" "$file"
      log "ADDED: $param='$newval' (inserted before </settings>)"
    else
      echo "    <param name=\"$param\" value=\"$newval\"/>" >> "$file"
      log "ADDED: $param='$newval' (appended at end - please verify XML structure)"
    fi
  fi
}

ensure_timer_name_timerfd() {
  local file="$1"
  local old; old="$(get_current_param_value "$file" "timer-name")"
  if grep -q "<param name=\"timer-name\"" "$file"; then
    if (( DRY_RUN == 1 )); then
      log "DRY-RUN: Would remove existing timer-name param(s) (was: '${old:-unknown}') in $file"
    else
      sed -i -E "/<param name=\"timer-name\"/d" "$file"
      log "REMOVED: existing timer-name param(s) (was: '${old:-unknown}')"
    fi
  fi
  if (( DRY_RUN == 1 )); then
    log "DRY-RUN: Would set timer-name -> 'timerfd' in $file"
    return 0
  fi
  if grep -q "</settings>" "$file"; then
    sed -i -E "s#</settings>#    <param name=\"timer-name\" value=\"timerfd\"/>\n</settings>#g" "$file"
    log "SET: timer-name -> 'timerfd'"
  else
    echo "    <param name=\"timer-name\" value=\"timerfd\"/>" >> "$file"
    log "SET: timer-name -> 'timerfd' (appended at end - please verify XML structure)"
  fi
}

read_sysctl_value() {
  local k="$1"
  local out rc
  out="$(sysctl -n "$k" 2>/dev/null || true)"
  rc=$?
  if [[ $rc -ne 0 || -z "$out" ]]; then
    echo "<unreadable>"
  else
    echo "$out"
  fi
}

ensure_systemd_execstart_foreground() {
  # Ensures -nf is present when Type=simple
  local unit_file="$1"
  [[ -f "$unit_file" ]] || return 0

  local type_line exec_line
  type_line="$(grep -E '^\s*Type=' "$unit_file" 2>/dev/null | tail -n 1 || true)"
  exec_line="$(grep -E '^\s*ExecStart=' "$unit_file" 2>/dev/null | tail -n 1 || true)"

  log "Inspecting unit for foreground requirement:"
  kv "Unit file" "$unit_file"
  kv "Type line" "${type_line:-<none>}"
  kv "ExecStart line" "${exec_line:-<none>}"

  # Only enforce if Type=simple or absent (default is simple)
  local type="simple"
  if [[ -n "$type_line" ]]; then
    type="$(echo "$type_line" | cut -d= -f2 | tr -d ' ')"
  fi

  if [[ "$type" != "simple" ]]; then
    log "No change: unit Type is '$type' (foreground enforcement only for Type=simple)."
    return 0
  fi

  if [[ "$exec_line" == *"freeswitch"* && "$exec_line" != *" -nf "* && "$exec_line" != *" -nf"* ]]; then
    # Insert -nf after 'freeswitch'
    if (( DRY_RUN == 1 )); then
      log "DRY-RUN: Would patch ExecStart to include -nf (foreground)."
      log "DRY-RUN: From: $exec_line"
      log "DRY-RUN: To:   $(echo "$exec_line" | sed -E 's#(freeswitch)([[:space:]]+)#\1\2-nf #')"
      return 0
    fi

    safe_backup "$unit_file"
    local new_line
    new_line="$(echo "$exec_line" | sed -E 's#(freeswitch)([[:space:]]+)#\1\2-nf #')"
    # Replace the exact ExecStart line we found (last one)
    # Simpler: replace first occurrence of 'ExecStart=...freeswitch ' with '...freeswitch -nf '
    sed -i -E "0,/^\\s*ExecStart=.*freeswitch[[:space:]]+/s//ExecStart=\\/usr\\/bin\\/freeswitch -nf /" "$unit_file" || true

    # If above didn't work due to different path, do a safer replace on the exact line string
    if ! grep -q "freeswitch -nf" "$unit_file"; then
      # Escape slashes
      local esc_old esc_new
      esc_old="$(printf '%s\n' "$exec_line" | sed 's/[\/&]/\\&/g')"
      esc_new="$(printf '%s\n' "$new_line" | sed 's/[\/&]/\\&/g')"
      sed -i "s/^$esc_old$/$esc_new/" "$unit_file" || true
    fi

    log "PATCHED: Added -nf to ExecStart (foreground)."
  else
    log "No change: ExecStart already includes -nf or doesn't match expected pattern."
  fi
}

install_watchdog_systemd_timer() {
  local fs_cli_path="${1:-/usr/bin/fs_cli}"
  local WATCHDOG="/usr/local/bin/fs_watchdog.sh"
  local WATCHDOG_LOG="/var/log/fs_watchdog.log"
  local SERVICE="/etc/systemd/system/fs-watchdog.service"
  local TIMER="/etc/systemd/system/fs-watchdog.timer"

  section "Watchdog via systemd timer (Debian-friendly)"
  safe_backup "$WATCHDOG"
  safe_backup "$SERVICE"
  safe_backup "$TIMER"

  if (( DRY_RUN == 1 )); then
    log "DRY-RUN: Would write watchdog script/service/timer"
    return 0
  fi

  cat >"$WATCHDOG" <<EOF
#!/bin/bash
set -euo pipefail
FS_CLI="$fs_cli_path"
LOG_FILE="$WATCHDOG_LOG"
CPU_LIMIT=60.0
timestamp() { date '+%Y-%m-%d %H:%M:%S'; }

echo "[\$(timestamp)] Watchdog run..." >> "\$LOG_FILE"

if ! systemctl is-active --quiet freeswitch; then
  echo "[\$(timestamp)] FAIL: FreeSWITCH not active -> restarting" >> "\$LOG_FILE"
  systemctl restart freeswitch
  exit 0
fi

if [[ ! -x "\$FS_CLI" ]]; then
  echo "[\$(timestamp)] WARN: fs_cli not found (\$FS_CLI). Only checking service state." >> "\$LOG_FILE"
  exit 0
fi

MAX_SESSIONS="\$("\$FS_CLI" -x "fsctl max_sessions" 2>/dev/null | awk '{print \$NF}' | head -n 1 || echo 0)"
CUR_SESSIONS="\$("\$FS_CLI" -x "show channels count" 2>/dev/null | tr -d '\\r' | tail -n 1 || echo 0)"
CPU_LOAD="\$(awk '{print \$1}' /proc/loadavg)"

MAX_SESSIONS="\${MAX_SESSIONS//[^0-9]/}"
CUR_SESSIONS="\${CUR_SESSIONS//[^0-9]/}"
MAX_SESSIONS="\${MAX_SESSIONS:-0}"
CUR_SESSIONS="\${CUR_SESSIONS:-0}"

if (( MAX_SESSIONS > 0 )) && (( CUR_SESSIONS >= MAX_SESSIONS - 100 )); then
  echo "[\$(timestamp)] WARN: Near max sessions (\$CUR_SESSIONS/\$MAX_SESSIONS) -> restarting" >> "\$LOG_FILE"
  systemctl restart freeswitch
  exit 0
fi

if command -v bc >/dev/null 2>&1; then
  LOAD_INT=\$(echo "\$CPU_LOAD > \$CPU_LIMIT" | bc -l)
  if (( LOAD_INT == 1 )); then
    echo "[\$(timestamp)] WARN: High load (\$CPU_LOAD) > \$CPU_LIMIT -> restarting" >> "\$LOG_FILE"
    systemctl restart freeswitch
    exit 0
  fi
else
  echo "[\$(timestamp)] INFO: bc not installed; skipping CPU threshold check (load=\$CPU_LOAD)" >> "\$LOG_FILE"
fi

echo "[\$(timestamp)] OK: Sessions=\$CUR_SESSIONS Max=\$MAX_SESSIONS Load=\$CPU_LOAD" >> "\$LOG_FILE"
EOF
  chmod +x "$WATCHDOG"

  cat >"$SERVICE" <<EOF
[Unit]
Description=FreeSWITCH Watchdog (checks and restarts if needed)
After=network.target

[Service]
Type=oneshot
ExecStart=$WATCHDOG
EOF

  cat >"$TIMER" <<EOF
[Unit]
Description=Run FreeSWITCH Watchdog every minute

[Timer]
OnBootSec=60s
OnUnitActiveSec=60s
AccuracySec=10s
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now fs-watchdog.timer >/dev/null 2>&1 || true
  log "OK: systemd watchdog timer enabled."
  systemctl status fs-watchdog.timer --no-pager | head -n 12 | tee -a "$LOG_FILE" || true
}

# ---------------------- MAIN ----------------------
parse_args "$@"
require_root

mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"

if [[ -n "$ROLLBACK_ID" ]]; then
  section "ROLLBACK MODE"
  kv "Rollback ID" "$ROLLBACK_ID"
  kv "Dry-run" "$DRY_RUN"

  rollback_file "/etc/sysctl.d/99-freeswitch.conf"
  rollback_file "/etc/systemd/system/freeswitch.service"
  rollback_file "/etc/systemd/system/freeswitch.service.d/override.conf"
  rollback_file "/usr/local/bin/fs_watchdog.sh"
  rollback_file "/etc/systemd/system/fs-watchdog.service"
  rollback_file "/etc/systemd/system/fs-watchdog.timer"

  if (( DRY_RUN == 0 )); then
    systemctl daemon-reload || true
    systemctl restart freeswitch || true
    systemctl restart fs-watchdog.timer || true
  else
    log "DRY-RUN: Would daemon-reload and restart services"
  fi
  section "Rollback Summary"
  log "DONE. Review report log: $LOG_FILE"
  exit 0
fi

section "FreeSWITCH Optimization Report (Run ID: $RUN_ID)"
kv "Host" "$HOST"
kv "Script" "$SCRIPT_NAME"
kv "Run mode" "$([[ $DRY_RUN -eq 1 ]] && echo "DRY-RUN (audit only)" || echo "APPLY changes")"
kv "Log file" "$LOG_FILE"
kv "Kernel" "$(uname -r)"
kv "OS" "$( (cat /etc/os-release 2>/dev/null | grep -E '^(PRETTY_NAME)=' | cut -d= -f2- | tr -d '"') || echo "Unknown" )"
[[ -f /etc/debian_version ]] && kv "Debian version" "$(cat /etc/debian_version)"

section "Hardware Detection"
CPU_CORES="$(nproc 2>/dev/null || echo 1)"
RAM_GB="$(free -g 2>/dev/null | awk '/^Mem:/{print $2}' || echo 0)"
kv "CPU cores detected" "$CPU_CORES"
kv "RAM detected (GB)" "$RAM_GB"

section "FreeSWITCH Installation Detection"
FS_BIN="$(detect_bin freeswitch || true)"
FS_CLI="$(detect_bin fs_cli || true)"
CONF_FILE="$(detect_conf_file || true)"

INSTALL_TYPE="unknown"
if [[ -d "/etc/freeswitch" || "${CONF_FILE:-}" == /etc/freeswitch/* ]]; then
  INSTALL_TYPE="package"
elif [[ -d "/usr/local/freeswitch" || "${CONF_FILE:-}" == /usr/local/freeswitch/* ]]; then
  INSTALL_TYPE="source"
fi

kv "Detected install type" "$INSTALL_TYPE"
kv "Detected freeswitch binary" "${FS_BIN:-NOT FOUND}"
kv "Detected fs_cli binary" "${FS_CLI:-NOT FOUND}"
kv "Detected switch.conf.xml" "${CONF_FILE:-NOT FOUND}"

log "systemd units containing 'freeswitch' (if any):"
list_fs_units | sed 's/^/ - /' | tee -a "$LOG_FILE" || true

if [[ -z "${FS_BIN:-}" ]]; then
  log "ERROR: 'freeswitch' binary not found in PATH. Aborting."
  exit 1
fi

FS_USER="root"; FS_GROUP="root"
if id freeswitch &>/dev/null; then
  if [[ "$INSTALL_TYPE" == "package" ]]; then
    FS_USER="freeswitch"; FS_GROUP="freeswitch"
  fi
fi
kv "Service run user (chosen)" "$FS_USER"
kv "Service run group (chosen)" "$FS_GROUP"

section "Stop FreeSWITCH safely"
# Stop watchdog timer during changes (prevents restart storm)
if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "fs-watchdog.timer"; then
  log "Temporarily disabling watchdog timer during changes..."
  run_cmd "systemctl disable --now fs-watchdog.timer || true"
fi

if detect_systemd_unit_exact "freeswitch.service"; then
  kv "systemd unit" "freeswitch.service FOUND"
  if systemctl is-active --quiet freeswitch; then
    log "Stopping FreeSWITCH via systemd..."
    run_cmd "systemctl stop freeswitch"
    sleep 2
  else
    log "FreeSWITCH not active under systemd."
  fi
else
  kv "systemd unit" "freeswitch.service NOT FOUND"
fi

if pgrep -x "freeswitch" >/dev/null 2>&1; then
  log "Found running FreeSWITCH process(es). Attempting graceful stop..."
  run_cmd "pkill -15 freeswitch || true"
  sleep 4
  if pgrep -x "freeswitch" >/dev/null 2>&1; then
    log "Force killing remaining freeswitch processes..."
    run_cmd "pkill -9 freeswitch || true"
  fi
  log "FreeSWITCH processes stopped."
else
  log "No running FreeSWITCH process found."
fi

section "Apply sysctl tuning (kernel/network)"
SYSCTL_FILE="/etc/sysctl.d/99-freeswitch.conf"
safe_backup "$SYSCTL_FILE"

log "Current sysctl values (before):"
for k in net.core.rmem_max net.core.wmem_max net.core.netdev_max_backlog net.ipv4.udp_mem net.ipv4.udp_rmem_min net.ipv4.udp_wmem_min fs.file-max; do
  kv "$k" "$(read_sysctl_value "$k")"
done

if (( DRY_RUN == 0 )); then
  cat >"$SYSCTL_FILE" <<EOF
# Generated by $SCRIPT_NAME ($RUN_ID)
net.core.rmem_max=26214400
net.core.wmem_max=26214400
net.core.netdev_max_backlog=250000
net.ipv4.udp_mem=65536 131072 262144
net.ipv4.udp_rmem_min=8192
net.ipv4.udp_wmem_min=8192
fs.file-max=2097152
EOF
  sysctl --system >/dev/null 2>&1 || true
  log "Applied sysctl settings from $SYSCTL_FILE"
else
  log "DRY-RUN: Would write $SYSCTL_FILE and apply sysctl --system"
fi

log "Sysctl values (after):"
for k in net.core.rmem_max net.core.wmem_max net.core.netdev_max_backlog net.ipv4.udp_mem net.ipv4.udp_rmem_min net.ipv4.udp_wmem_min fs.file-max; do
  kv "$k" "$(read_sysctl_value "$k")"
done

section "Tune FreeSWITCH core config (switch.conf.xml)"
if [[ -n "${CONF_FILE:-}" && -f "$CONF_FILE" ]]; then
  safe_backup "$CONF_FILE"
  log "Before values:"
  kv "max-sessions" "$(get_current_param_value "$CONF_FILE" "max-sessions")"
  kv "sessions-per-second" "$(get_current_param_value "$CONF_FILE" "sessions-per-second")"
  kv "loglevel" "$(get_current_param_value "$CONF_FILE" "loglevel")"
  kv "timer-name" "$(get_current_param_value "$CONF_FILE" "timer-name")"

  set_or_insert_param "$CONF_FILE" "max-sessions" "15000"
  set_or_insert_param "$CONF_FILE" "sessions-per-second" "800"
  set_or_insert_param "$CONF_FILE" "loglevel" "warning"
  ensure_timer_name_timerfd "$CONF_FILE"

  log "After values:"
  kv "max-sessions" "$(get_current_param_value "$CONF_FILE" "max-sessions")"
  kv "sessions-per-second" "$(get_current_param_value "$CONF_FILE" "sessions-per-second")"
  kv "loglevel" "$(get_current_param_value "$CONF_FILE" "loglevel")"
  kv "timer-name" "$(get_current_param_value "$CONF_FILE" "timer-name")"
else
  log "SKIPPED: switch.conf.xml tuning (file not found)."
fi

section "systemd setup (ensure correct foreground behavior)"
SERVICE_FILE="/etc/systemd/system/freeswitch.service"

# If no unit exists, create one (Type=simple + -nf)
if ! detect_systemd_unit_exact "freeswitch.service"; then
  log "No freeswitch.service registered. Creating $SERVICE_FILE (Type=simple + -nf)..."
  safe_backup "$SERVICE_FILE"
  if (( DRY_RUN == 0 )); then
    cat >"$SERVICE_FILE" <<EOF
[Unit]
Description=FreeSWITCH Service
After=network.target local-fs.target

[Service]
Type=simple
User=$FS_USER
Group=$FS_GROUP
ExecStart=$FS_BIN -nf -ncwait -nonat
ExecStop=${FS_CLI:-/usr/bin/fs_cli} -x "shutdown elegant"
ExecReload=${FS_CLI:-/usr/bin/fs_cli} -x "reloadxml"
Restart=always
RestartSec=5

LimitCORE=infinity
LimitNOFILE=65535
LimitNPROC=65535
TasksMax=infinity

[Install]
WantedBy=multi-user.target
EOF
  else
    log "DRY-RUN: Would create $SERVICE_FILE"
  fi
else
  log "freeswitch.service exists. Ensuring ExecStart includes -nf if Type=simple..."
  ensure_systemd_execstart_foreground "$SERVICE_FILE"
fi

# Override drop-in remains fine; keep it.
OVR_DIR="/etc/systemd/system/freeswitch.service.d"
OVR_FILE="$OVR_DIR/override.conf"
run_cmd "mkdir -p \"$OVR_DIR\""
safe_backup "$OVR_FILE"
if (( DRY_RUN == 0 )); then
  cat >"$OVR_FILE" <<EOF
# Generated by $SCRIPT_NAME ($RUN_ID)
[Service]
Restart=always
RestartSec=5
LimitCORE=infinity
LimitNOFILE=65535
LimitNPROC=65535
TasksMax=infinity
CPUAffinity=0-$((CPU_CORES-1))
EOF
else
  log "DRY-RUN: Would write override $OVR_FILE"
fi

if (( DRY_RUN == 0 )); then
  systemctl daemon-reload
  systemctl enable freeswitch >/dev/null 2>&1 || true
  systemctl restart freeswitch || true
else
  log "DRY-RUN: Would daemon-reload + restart freeswitch"
fi

sleep 3
if systemctl is-active --quiet freeswitch; then
  log "OK: FreeSWITCH is active (running) under systemd."
else
  log "ERROR: FreeSWITCH not active after restart."
  log "Hint: journalctl -u freeswitch --no-pager -n 200"
fi

# Reinstall watchdog timer and re-enable
install_watchdog_systemd_timer "${FS_CLI:-/usr/bin/fs_cli}"

section "Final Summary"
log "FreeSWITCH status (top lines):"
systemctl status freeswitch --no-pager | head -n 25 | tee -a "$LOG_FILE" || true

log "DONE. Report log: $LOG_FILE"
log "Run ID for rollback: $RUN_ID"
log "To rollback this run: sudo ./$SCRIPT_NAME --rollback $RUN_ID"
