FS=/usr/local/bin/fs_cli
echo "=== resolved FS dirs ==="
for v in base_dir mod_dir script_dir log_dir conf_dir; do printf "  %-11s %s\n" "$v" "$($FS -x "eval \${$v}" 2>&1 | head -1)"; done
echo
echo "=== where loaded modules come from (path histogram) ==="
$FS -x "show modules" 2>/dev/null | awk -F, 'NF>=4{n=split($4,a,"/"); sub("/"a[n]"$","",$4); c[$4]++} END{for(k in c) printf "  %5d  %s\n", c[k], k}' | sort -rn
echo
echo "=== candidate module dirs ==="
for d in /var/lib/freeswitch/mod /opt/voip/fs/mod /usr/local/freeswitch/mod /usr/local/lib/freeswitch/mod; do
  if [ -d "$d" ]; then printf "  %-34s %4s files  curl:%s  lua:%s  %s\n" "$d" "$(ls $d 2>/dev/null | wc -l)" "$([ -e $d/mod_curl.so ] && echo yes || echo NO)" "$([ -e $d/mod_lua.so ] && echo yes || echo NO)" "$(ls -ld $d | awk '{print $1, $NF}' | cut -c1-60)"
  else printf "  %-34s (absent)\n" "$d"; fi
done
echo "  /var/lib/freeswitch/mod sample:"; ls -la /var/lib/freeswitch/mod 2>/dev/null | head -4 | cut -c1-140
echo
echo "=== systemd ExecStart ==="; systemctl cat freeswitch 2>/dev/null | grep -A7 "^ExecStart" | tr -s " " | tr "\n" " " | cut -c1-260; echo
echo
echo "=== FS log: module load failures (any file under log_dir) ==="
LD=$($FS -x 'eval ${log_dir}' 2>/dev/null); ls -la "$LD" 2>/dev/null | head -5
grep -ahiE "mod_curl|Error Loading module|Failure|cannot open shared" "$LD"/freeswitch.log* 2>/dev/null | tail -6 || true
echo "  (end)"
echo
echo "=== try loading mod_curl now (dry: see the error only) ==="
$FS -x "load mod_curl" 2>&1 | head -2
