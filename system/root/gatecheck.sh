cd /opt/voip
D=$(date +%Y%m%d); DD=$(date +%Y-%m-%d)
echo "=== today: recordings vs gate decisions (fixed quoting) ==="
echo "  recordings today:     $(ls recordings/3366_${D}_*.wav 2>/dev/null | wc -l)"
echo "  decisions today:      $(grep -c "\"when\":\"${DD}" companies/decisions/2026-09.jsonl 2>/dev/null)"
echo "  decisions total:      $(wc -l < companies/decisions/2026-09.jsonl)"
echo "  recordings last 7d:   $(find recordings -name '3366_2026092[2-8]_*.wav' | wc -l)"
echo
echo "=== is mod_curl loaded? (the lua calls freeswitch.API():execute(\"curl\", ...)) ==="
/usr/local/bin/fs_cli -x "show modules" 2>&1 | grep -iE "mod_curl|api,curl" | head -3 || true
echo "  curl api test: $(/usr/local/bin/fs_cli -x 'curl http://127.0.0.1:8080/login timeout 3' 2>&1 | head -c 120)"
echo
echo "=== FreeSWITCH log: gate / lua / curl errors today ==="
grep -aiE "gate|record_and_bridge|mod_lua|curl" /var/log/freeswitch/freeswitch.log 2>/dev/null | grep -aiE "err|fail|invalid|not found|timeout" | tail -6
echo "  (end)"
echo
echo "=== did the lua even run for today's calls? (dialplan hits) ==="
grep -ac "record_and_bridge_3366" /var/log/freeswitch/freeswitch.log 2>/dev/null | xargs echo "  lua mentions in log:"
grep -a "record_and_bridge_3366" /var/log/freeswitch/freeswitch.log 2>/dev/null | tail -3 | cut -c1-200
echo
echo "=== panel side: gate endpoint hits today (security/gate log lines) ==="
journalctl -u voip-frontend --since today --no-pager 2>/dev/null | grep -iE "gate" | tail -5 || echo "  none"
