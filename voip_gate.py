"""Pre-answer decision engine for the 3366 honeypot.

FreeSWITCH (record_and_bridge_3366.lua) posts every inbound call here before answering.
The engine scores the A number, B number and source/media IP against lists, numbering data,
reputation feeds, the platform's own audio verdicts and live velocity counters, and returns
allow / flag / decline with reason codes.  Every decision is appended to a monthly JSONL log
that the panel exposes (Decisions page, dashboard tiles, traceback packets).

Per-trunk gate mode:  off      - score and log only for visibility, never marked enforceable
                      record   - score, log, mark what *would* be declined (default)
                      enforce  - FreeSWITCH rejects declines with SIP 603 (503 for CPS)
"""
import os, re, json, time, threading, ipaddress, collections, csv, datetime
import urllib.request, urllib.error

COMP_DIR = "/opt/voip/companies"
GATE_CFG = os.path.join(COMP_DIR, "gate.json")
DNO_FILE = os.path.join(COMP_DIR, "dno.txt")
DIALER_FILE = os.path.join(COMP_DIR, "dialer_agents.txt")
SCANNER_FILE = os.path.join(COMP_DIR, "scanner_ips.tsv")
NPA_FILE = os.path.join(COMP_DIR, "npa_report.csv")
NPANXX_FILE = os.path.join(COMP_DIR, "npanxx_allocated.txt")
DECISIONS_DIR = os.path.join(COMP_DIR, "decisions")
VERDICT_FILE = os.path.join(COMP_DIR, "verdicts.json")
FTC_DIR = "/opt/voip/spam_reputation_current"
FORCE_ANI_FILE = os.path.join(COMP_DIR, "force_ani.txt")
FORCE_IP_FILE = os.path.join(COMP_DIR, "force_ip.txt")
ALLOW_ANI_FILE = os.path.join(COMP_DIR, "allow_ani.txt")
ALLOW_IP_FILE = os.path.join(COMP_DIR, "allow_ip.txt")
HIGH_COST_FILE = os.path.join(COMP_DIR, "high_cost_prefixes.txt")      # international E.164 prefixes (IRSF / premium / satellite)
HIGH_COST_NPANXX_FILE = os.path.join(COMP_DIR, "high_cost_npanxx.txt")  # NANP NPA-NXX with access-stimulation / high terminating rates
LOOKUP_CACHE = os.path.join(COMP_DIR, "lookups.json")
DISPUTES_FILE = os.path.join(COMP_DIR, "disputes.jsonl")

DEFAULTS = {"default_mode": "record", "threshold": 60, "flag_threshold": 30, "cps": 0,
            "ani_5m": 30, "ip_5m": 120, "anis_per_hour": 200, "retention_days": 0,
            "dispute_contact": "", "stir_wait": 1.5, "verdict_days": 30,
            "lookup_provider": "", "lookup_key": "", "lookup_daily_cap": 500, "dest_per_hour": 30,
            "model_enabled": 0, "model_mode": "shadow", "model_url": "", "model_key": "",
            "model_name": "jev-1", "model_timeout": 1.2, "model_max_points": 40, "model_can_decline": 0}
STRING_SETTINGS = ("dispute_contact", "lookup_provider", "lookup_key", "model_mode", "model_url", "model_key", "model_name")
LOOKUP_PROVIDERS = ("", "telnyx", "twilio")
MODES = ("off", "record", "enforce")
MODEL_MODES = ("shadow", "advisory", "active")
TOLLFREE_NPA = {"800", "833", "844", "855", "866", "877", "888"}
PREMIUM_NPA = {"900", "976"}

REASONS = {
    "FORCE_ANI": "Calling number is on a block list",
    "FORCE_IP": "Source IP is on a block list",
    "DNO": "Calling number is on the Do Not Originate list",
    "CPS_LIMIT": "Trunk calls-per-second limit exceeded",
    "ALLOW_ANI": "Calling number is on the allow list",
    "ALLOW_IP": "Source IP is on the allow list",
    "CONSENT": "Consent on record for this calling and called number",
    "VERDICT_ANI": "Calling number was classified fraud or illegal robocall by audio analysis",
    "VERDICT_IP": "Source IP carried calls classified fraud or illegal robocall",
    "STIR_FAILED": "STIR/SHAKEN signature failed verification",
    "STIR_MISSING": "No STIR/SHAKEN Identity header",
    "STIR_ATTEST_C": "Gateway attestation (C)",
    "STIR_ATTEST_B": "Partial attestation (B)",
    "STIR_PENDING": "STIR/SHAKEN verification did not finish before answer",
    "NEIGHBOR_SPOOF": "Calling number shares NPA-NXX with the called number",
    "ANI_INVALID": "Calling number is not a valid NANP or international number",
    "ANI_NPA_UNASSIGNED": "Calling number area code is not assigned or not in service",
    "ANI_NXX_UNALLOCATED": "Calling number NPA-NXX is not allocated to any carrier",
    "ANI_TOLLFREE": "Calling number is a toll-free number",
    "ANI_PREMIUM": "Calling number is a premium-rate number",
    "ANI_NOT_DECLARED": "Calling number is outside the trunk's declared number ranges",
    "FTC_COMPLAINTS": "FTC Do Not Call complaints against the calling number",
    "MEDIA_IP_MISMATCH": "Media IP differs from the signalling IP",
    "SCANNER_IP": "Source IP has probed this switch for SIP accounts",
    "DIALER_AGENT": "SIP User-Agent matches known dialer or scanner software",
    "ANI_VELOCITY": "Too many calls from this calling number in 5 minutes",
    "IP_VELOCITY": "Too many calls from this source IP in 5 minutes",
    "SNOWSHOE": "Too many distinct calling numbers from this trunk in one hour",
    "WANGIRI_PATTERN": "Repeated short international calls from one number",
    "LOW_ASR_ACD": "Calling number has a low answer rate and very short calls",
    "DNC_NO_CONSENT": "Called number is on Do Not Call and no consent is on record",
    "UNKNOWN_SOURCE": "Source IP belongs to no customer trunk",
    "DNI_HIGH_COST": "Called number is in a high-cost international range (IRSF / premium / satellite)",
    "IRSF_PATTERN": "Burst of calls from one number to high-cost destinations",
    "DNI_TRAFFIC_PUMPING": "Called NPA-NXX is on the access-stimulation (traffic pumping) list",
    "ACCESS_STIMULATION": "Trunk is concentrating calls on one NPA-NXX this hour",
    "LINE_TYPE_VOIP": "Calling number is a VoIP line (lookup)",
    "LINE_TYPE_MISMATCH": "Calling number line type does not fit the traffic (toll-free or landline presented from a VoIP trunk)",
    "LOOKUP_PENDING": "Carrier lookup for the calling number is still in progress",
    "MODEL_RISK": "Structured-decision model flagged this call as risky",
}

_LOCK = threading.RLock()
_HOOKS = {}
_FILE_CACHE = {}
_CFG = {"mtime": None, "value": None}
_FTC_CACHE = {}
_VERDICTS = {"at": 0.0, "value": None}
_ANI_STATS = {"at": 0.0, "value": None}


def set_hooks(**kw):
    """Hooks supplied by app.py: list_recordings, snapshot_calls, stir_verify, company_by_id, company_lists,
    company_for, trunk_for, company_label, trunk_label."""
    _HOOKS.update(kw)


# ----------------------------------------------------------------------------- config
def load_cfg():
    try:
        st = os.stat(GATE_CFG)
        key = (st.st_mtime_ns, st.st_size)
    except OSError:
        key = None
    with _LOCK:
        if _CFG["mtime"] == key and _CFG["value"] is not None:
            return dict(_CFG["value"])
        value = dict(DEFAULTS)
        if key is not None:
            try:
                with open(GATE_CFG, encoding="utf-8") as f:
                    data = json.load(f)
                for k in DEFAULTS:
                    if k in data:
                        value[k] = data[k]
            except (OSError, ValueError):
                pass
        _CFG["mtime"], _CFG["value"] = key, value
        return dict(value)


def save_cfg(values):
    cur = load_cfg()
    for k, v in (values or {}).items():
        if k not in DEFAULTS:
            return {"ok": False, "error": "unknown setting %s" % k}
        if k == "default_mode":
            if v not in MODES:
                return {"ok": False, "error": "mode must be off, record or enforce"}
            cur[k] = v
        elif k in STRING_SETTINGS:
            v = str(v or "").strip()[:200]
            if k == "lookup_provider" and v not in LOOKUP_PROVIDERS:
                return {"ok": False, "error": "lookup provider must be telnyx, twilio or empty"}
            if k == "lookup_key" and v == "••••••••":
                continue  # masked value from the form: keep the stored key
            if k == "model_mode" and v not in MODEL_MODES:
                return {"ok": False, "error": "model_mode must be shadow, advisory or active"}
            if k == "model_key" and v == "••••••••":
                continue  # masked value from the form: keep the stored key
            cur[k] = v
        elif k == "stir_wait":
            try: cur[k] = max(0.0, min(4.0, float(v)))
            except (TypeError, ValueError): return {"ok": False, "error": "stir_wait must be a number"}
        elif k == "model_timeout":
            try: cur[k] = max(0.1, min(5.0, float(v)))
            except (TypeError, ValueError): return {"ok": False, "error": "model_timeout must be a number"}
        else:
            try: cur[k] = max(0, int(v))
            except (TypeError, ValueError): return {"ok": False, "error": "%s must be a whole number" % k}
    os.makedirs(COMP_DIR, exist_ok=True)
    tmp = GATE_CFG + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cur, f, indent=1)
    os.replace(tmp, GATE_CFG)
    with _LOCK:
        _CFG["mtime"] = None
    return {"ok": True, "settings": cur}


def public_cfg():
    c = load_cfg()
    if c.get("lookup_key"):
        c["lookup_key"] = "••••••••"
    if c.get("model_key"):
        c["model_key"] = "••••••••"
    return c


def read_text_list(path):
    """Lines of a list file (comments and blanks removed), cached by mtime."""
    try:
        st = os.stat(path); key = (st.st_mtime_ns, st.st_size)
    except OSError:
        return []
    with _LOCK:
        hit = _FILE_CACHE.get(path)
        if hit and hit[0] == key:
            return hit[1]
    out = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if line:
                    out.append(line)
    except OSError:
        pass
    with _LOCK:
        _FILE_CACHE[path] = (key, out)
    return out


def write_text_list(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(str(text or "").replace("\r", "").strip() + "\n")
    os.replace(tmp, path)


def read_text_file(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


# ----------------------------------------------------------------------------- numbers
def normalize_number(raw):
    """E.164-style normalisation with country detection for the two things this platform sees:
    NANP numbers (10/11 digits) and international numbers dialed with +, 00 or 011."""
    s = str(raw or "").strip()
    plus = s.startswith("+")
    d = re.sub(r"\D", "", s)
    out = {"raw": s, "digits": d, "e164": "", "kind": "invalid", "npa": "", "nxx": "", "country": ""}
    if not d:
        return out
    intl = plus
    if not plus and d.startswith("011") and len(d) > 11:
        d = d[3:]; intl = True
    elif not plus and d.startswith("00") and len(d) > 11:
        d = d[2:]; intl = True
    if len(d) == 11 and d[0] == "1":
        d10 = d[1:]
    elif len(d) == 10 and not intl:
        d10 = d
    else:
        d10 = ""
    if d10 and re.fullmatch(r"[2-9]\d\d[2-9]\d{6}", d10) and d10[1:3] != "11" and d10[4:6] != "11":
        out.update({"e164": "+1" + d10, "kind": "nanp", "npa": d10[:3], "nxx": d10[3:6], "country": "US/CA"})
        return out
    if len(d) >= 8 and len(d) <= 15 and (intl or d[0] != "1"):
        out.update({"e164": "+" + d, "kind": "intl", "country": _country_of(d)})
        return out
    if len(d) < 7:
        out["kind"] = "short"
    return out


_CC = {"1": "US/CA", "7": "RU/KZ", "20": "EG", "27": "ZA", "30": "GR", "31": "NL", "32": "BE", "33": "FR", "34": "ES", "36": "HU",
       "39": "IT", "40": "RO", "41": "CH", "43": "AT", "44": "GB", "45": "DK", "46": "SE", "47": "NO", "48": "PL", "49": "DE",
       "51": "PE", "52": "MX", "53": "CU", "54": "AR", "55": "BR", "56": "CL", "57": "CO", "58": "VE", "60": "MY", "61": "AU",
       "62": "ID", "63": "PH", "64": "NZ", "65": "SG", "66": "TH", "81": "JP", "82": "KR", "84": "VN", "86": "CN", "90": "TR",
       "91": "IN", "92": "PK", "93": "AF", "94": "LK", "95": "MM", "98": "IR", "212": "MA", "213": "DZ", "216": "TN", "218": "LY",
       "220": "GM", "221": "SN", "223": "ML", "225": "CI", "228": "TG", "229": "BJ", "230": "MU", "231": "LR", "232": "SL",
       "233": "GH", "234": "NG", "237": "CM", "241": "GA", "243": "CD", "249": "SD", "250": "RW", "251": "ET", "252": "SO",
       "253": "DJ", "254": "KE", "255": "TZ", "256": "UG", "260": "ZM", "263": "ZW", "264": "NA", "265": "MW", "266": "LS",
       "268": "SZ", "351": "PT", "352": "LU", "353": "IE", "354": "IS", "355": "AL", "356": "MT", "357": "CY", "358": "FI",
       "359": "BG", "370": "LT", "371": "LV", "372": "EE", "373": "MD", "374": "AM", "375": "BY", "380": "UA", "381": "RS",
       "385": "HR", "386": "SI", "387": "BA", "389": "MK", "420": "CZ", "421": "SK", "423": "LI", "501": "BZ", "502": "GT",
       "503": "SV", "504": "HN", "505": "NI", "506": "CR", "507": "PA", "509": "HT", "591": "BO", "593": "EC", "595": "PY",
       "598": "UY", "673": "BN", "675": "PG", "679": "FJ", "852": "HK", "853": "MO", "855": "KH", "856": "LA", "880": "BD",
       "886": "TW", "960": "MV", "961": "LB", "962": "JO", "963": "SY", "964": "IQ", "965": "KW", "966": "SA", "967": "YE",
       "968": "OM", "970": "PS", "971": "AE", "972": "IL", "973": "BH", "974": "QA", "975": "BT", "976": "MN", "977": "NP",
       "992": "TJ", "993": "TM", "994": "AZ", "995": "GE", "996": "KG", "998": "UZ"}


def _country_of(d):
    for n in (3, 2, 1):
        if d[:n] in _CC:
            return _CC[d[:n]]
    return "??"


def npa_table():
    """NPA report from NANPA (reports.nanpa.com/public/npa_report.csv) -> {npa: {assigned, in_service, location, country}}."""
    try:
        st = os.stat(NPA_FILE); key = (st.st_mtime_ns, st.st_size)
    except OSError:
        return {}
    with _LOCK:
        hit = _FILE_CACHE.get(NPA_FILE)
        if hit and hit[0] == key:
            return hit[1]
    table = {}
    try:
        with open(NPA_FILE, encoding="utf-8", errors="replace") as f:
            lines = f.read().split("\n")
        start = next((i for i, l in enumerate(lines) if l.startswith("NPA_ID")), None)
        if start is not None:
            for row in csv.DictReader(lines[start:]):
                npa = (row.get("NPA_ID") or "").strip()
                if not re.fullmatch(r"\d{3}", npa):
                    continue
                table[npa] = {"assigned": (row.get("ASSIGNED") or "").strip().upper().startswith("Y"),
                              "in_service": (row.get("IN_SERVICE") or "").strip().upper().startswith("Y"),
                              "location": (row.get("LOCATION") or "").strip(), "country": (row.get("COUNTRY") or "").strip(),
                              "type": (row.get("type_of_code") or "").strip()}
    except OSError:
        pass
    with _LOCK:
        _FILE_CACHE[NPA_FILE] = (key, table)
    return table


def npanxx_allocated():
    """Optional set of allocated NPA-NXX (6 digits per line) when the NANPA CO code file has been loaded."""
    return set(read_text_list(NPANXX_FILE))


def number_facts(raw):
    """Everything the panel shows about a number: normalisation plus NANP allocation facts."""
    n = normalize_number(raw)
    n["flags"] = []
    if n["kind"] == "nanp":
        info = npa_table().get(n["npa"])
        if info:
            n["region"] = ", ".join(x for x in (info.get("location"), info.get("country")) if x)
            if not (info["assigned"] and info["in_service"]):
                n["flags"].append("ANI_NPA_UNASSIGNED")
        alloc = npanxx_allocated()
        if alloc and (n["npa"] + n["nxx"]) not in alloc:
            n["flags"].append("ANI_NXX_UNALLOCATED")
        if n["npa"] in TOLLFREE_NPA:
            n["flags"].append("ANI_TOLLFREE")
        if n["npa"] in PREMIUM_NPA:
            n["flags"].append("ANI_PREMIUM")
    elif n["kind"] in ("invalid", "short"):
        n["flags"].append("ANI_INVALID")
    return n


# ----------------------------------------------------------------------------- reputation feeds
def ftc_lookup(number):
    """FTC DNC complaint counts for a number from the nightly reputation build (per-NPA TSV files)."""
    d = re.sub(r"\D", "", str(number or ""))
    if len(d) == 11 and d[0] == "1":
        d = d[1:]
    if len(d) != 10:
        return None
    path = os.path.join(FTC_DIR, d[:3] + ".tsv")
    try:
        st = os.stat(path); key = (st.st_mtime_ns, st.st_size)
    except OSError:
        return None
    with _LOCK:
        hit = _FTC_CACHE.get(path)
    if not hit or hit[0] != key:
        table = {}
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    parts = line.rstrip("\n").split("\t")
                    if len(parts) >= 3:
                        num = parts[0]
                        if len(num) == 11 and num[0] == "1":
                            num = num[1:]
                        try:
                            table[num] = {"complaints": int(parts[1]), "robocalls": int(parts[2]), "last_seen": parts[3] if len(parts) > 3 else ""}
                        except ValueError:
                            continue
        except OSError:
            table = {}
        hit = (key, table)
        with _LOCK:
            _FTC_CACHE[path] = hit
    return hit[1].get(d)


def scanner_ips():
    """{ip: {count, last}} built by update_voip_scanner_ips from the FreeSWITCH log."""
    out = {}
    for line in read_text_list(SCANNER_FILE):
        parts = line.split("\t")
        if len(parts) >= 2:
            try:
                out[parts[0]] = {"count": int(parts[1]), "last": parts[2] if len(parts) > 2 else ""}
            except ValueError:
                continue
    return out


def dialer_patterns():
    return [p.lower() for p in read_text_list(DIALER_FILE)]


def dno_numbers():
    return {re.sub(r"\D", "", x)[-10:] for x in read_text_list(DNO_FILE) if re.sub(r"\D", "", x)}


_REFRESHING = set()


def _refresh_in_background(name, fn):
    """Run fn once in a daemon thread unless a refresh with the same name is already running."""
    with _LOCK:
        if name in _REFRESHING:
            return
        _REFRESHING.add(name)
    def run():
        try: fn()
        except Exception as e: print("gate background %s failed: %s" % (name, e), flush=True)
        finally:
            with _LOCK: _REFRESHING.discard(name)
    threading.Thread(target=run, daemon=True).start()


def verdict_lists(force=False):
    """The platform's own evidence: ANIs and source IPs of calls the audio analysis classified as fraud or
    illegal robocall within the last verdict_days. Cached five minutes and mirrored to verdicts.json.
    The pre-answer path never waits for a refresh: a stale value is served while a background thread rebuilds."""
    now = time.time()
    with _LOCK:
        cur = _VERDICTS["value"]; age = now - _VERDICTS["at"]
    if not force and cur is not None:
        if age >= 300:
            _refresh_in_background("verdicts", lambda: _verdict_build(True))
        return cur
    if not force:
        # cold: never block the pre-answer path; build once in the background and serve an empty list meanwhile
        _refresh_in_background("verdicts", lambda: _verdict_build(True))
        return {"generated": 0, "days": 0, "anis": {}, "ips": {}}
    return _verdict_build(force)


def _verdict_build(force=False):
    now = time.time()
    cfg = load_cfg()
    days = int(cfg.get("verdict_days") or 30)
    cutoff = (datetime.datetime.utcnow() - datetime.timedelta(days=days)).strftime("%Y-%m-%d")
    anis, ips = {}, {}
    try:
        calls = _HOOKS["snapshot_calls"]() if "snapshot_calls" in _HOOKS else []
        recs = {r["file"]: r for r in (_HOOKS["list_recordings"]() if "list_recordings" in _HOOKS else [])}
        for c in calls:
            if c.get("classification") not in ("fraud", "illegal_robocall"):
                continue
            when = str(c.get("when") or "")[:10]
            if when < cutoff:
                continue
            ani = re.sub(r"\D", "", str(c.get("ani") or ""))
            if len(ani) == 11 and ani[0] == "1":
                ani = ani[1:]
            if ani and ani != "unknown":
                e = anis.setdefault(ani, {"count": 0, "last": "", "classification": c.get("classification"), "category": c.get("category_label") or ""})
                e["count"] += 1
                if when > e["last"]: e["last"] = when
            rec = recs.get(c.get("file")) or {}
            ip = str(rec.get("sig_ip") or "")
            if ip and ip not in ("-", "0.0.0.0") and not rec.get("simulated"):
                # a customer's own trunk IP is never a verdict: the customer is the victim of its caller, not the fraudster
                if "company_for" in _HOOKS and _HOOKS["company_for"](ip, ""):
                    continue
                e = ips.setdefault(ip, {"count": 0, "last": ""})
                e["count"] += 1
                if when > e["last"]: e["last"] = when
    except Exception as e:  # never let a verdict refresh break call handling
        print("gate verdict refresh failed: %s" % e, flush=True)
    value = {"generated": int(now), "days": days, "anis": anis, "ips": ips}
    with _LOCK:
        _VERDICTS["at"], _VERDICTS["value"] = now, value
    try:
        os.makedirs(COMP_DIR, exist_ok=True)
        tmp = VERDICT_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(value, f)
        os.replace(tmp, VERDICT_FILE)
    except OSError:
        pass
    return value


def ani_stats():
    """Per-ANI attempts / connected / billsec over the last 24h from the recordings index (60 s cache,
    refreshed in the background so the pre-answer path never blocks on the recordings index)."""
    now = time.time()
    with _LOCK:
        cur = _ANI_STATS["value"]; age = now - _ANI_STATS["at"]
    if cur is not None:
        if age >= 60:
            _refresh_in_background("ani_stats", _ani_stats_build)
        return cur
    _refresh_in_background("ani_stats", _ani_stats_build)
    return {}


def _ani_stats_build():
    now = time.time()
    stats = {}
    try:
        cutoff = now - 86400
        for r in (_HOOKS["list_recordings"]() if "list_recordings" in _HOOKS else []):
            if float(r.get("mtime") or 0) < cutoff:
                continue
            ani = re.sub(r"\D", "", str(r.get("ani") or ""))
            if not ani:
                continue
            e = stats.setdefault(ani, {"attempts": 0, "connected": 0, "billsec": 0.0, "short": 0})
            e["attempts"] += 1
            if r.get("connected"):
                e["connected"] += 1
                b = r.get("billsec")
                if b is None:
                    b = max(0.0, (int(r.get("size") or 0) - 44) / 16000.0)
                e["billsec"] += float(b)
                if float(b) < 6: e["short"] += 1
    except Exception:
        stats = {}
    with _LOCK:
        _ANI_STATS["at"], _ANI_STATS["value"] = now, stats
    return stats


# ----------------------------------------------------------------------------- number lookup (CNAM, line type, carrier)
_LOOKUP = {"key": None, "table": {}, "lock": threading.Lock(), "inflight": set(), "day": "", "count": 0}


def _lookup_table():
    try:
        st = os.stat(LOOKUP_CACHE); key = (st.st_mtime_ns, st.st_size)
    except OSError:
        key = None
    with _LOOKUP["lock"]:
        if _LOOKUP["key"] != key:
            table = {}
            if key is not None:
                try:
                    with open(LOOKUP_CACHE, encoding="utf-8") as f:
                        table = json.load(f)
                except (OSError, ValueError):
                    table = {}
            _LOOKUP["key"], _LOOKUP["table"] = key, table
        return _LOOKUP["table"]


def _lookup_store(e164, entry):
    with _LOOKUP["lock"]:
        table = dict(_LOOKUP["table"]); table[e164] = entry
        if len(table) > 200000:
            for k in sorted(table, key=lambda k: table[k].get("ts", 0))[:50000]:
                table.pop(k, None)
        try:
            tmp = LOOKUP_CACHE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(table, f)
            os.replace(tmp, LOOKUP_CACHE)
            st = os.stat(LOOKUP_CACHE); _LOOKUP["key"] = (st.st_mtime_ns, st.st_size)
        except OSError:
            pass
        _LOOKUP["table"] = table


def _lookup_fetch(e164, cfg):
    """One provider call. Returns {line_type, carrier, cnam, provider} or {"error": ...}."""
    import urllib.request, base64
    provider, key = cfg.get("lookup_provider") or "", cfg.get("lookup_key") or ""
    try:
        if provider == "telnyx":
            req = urllib.request.Request("https://api.telnyx.com/v2/number_lookup/%s?type=carrier&type=caller-name" % e164,
                                         headers={"Authorization": "Bearer " + key, "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=4) as r:
                d = (json.loads(r.read().decode("utf-8")) or {}).get("data") or {}
            car = d.get("carrier") or {}; cn = d.get("caller_name") or {}
            return {"line_type": str(car.get("type") or "").lower(), "carrier": str(car.get("name") or ""), "cnam": str(cn.get("caller_name") or ""), "provider": provider}
        if provider == "twilio":
            if ":" not in key:
                return {"error": "twilio key must be SID:AUTH_TOKEN"}
            auth = base64.b64encode(key.encode()).decode()
            req = urllib.request.Request("https://lookups.twilio.com/v2/PhoneNumbers/%s?Fields=line_type_intelligence,caller_name" % e164,
                                         headers={"Authorization": "Basic " + auth, "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=4) as r:
                d = json.loads(r.read().decode("utf-8")) or {}
            lti = d.get("line_type_intelligence") or {}; cn = d.get("caller_name") or {}
            lt = str(lti.get("type") or "").lower()
            lt = {"nonfixedvoip": "voip", "fixedvoip": "voip", "landline": "landline", "mobile": "mobile", "tollfree": "toll-free"}.get(lt.replace("_", ""), lt)
            return {"line_type": lt, "carrier": str(lti.get("carrier_name") or ""), "cnam": str(cn.get("caller_name") or ""), "provider": provider}
        return {"error": "no provider configured"}
    except Exception as e:
        return {"error": str(e)[:120]}


def number_lookup(number, allow_fetch=False, background=True):
    """Cached CNAM / line type / carrier for a number. With allow_fetch the provider is called (synchronously,
    or in the background when background=True so the pre-answer path never waits on it). Daily cap protects cost."""
    n = normalize_number(number)
    e164 = n.get("e164")
    if not e164:
        return None
    hit = _lookup_table().get(e164)
    if hit and (time.time() - float(hit.get("ts") or 0)) < 30 * 86400:
        return hit
    cfg = load_cfg()
    if not allow_fetch or not cfg.get("lookup_provider") or not cfg.get("lookup_key"):
        return hit
    today = time.strftime("%Y-%m-%d")
    with _LOOKUP["lock"]:
        if _LOOKUP["day"] != today:
            _LOOKUP["day"], _LOOKUP["count"] = today, 0
        if _LOOKUP["count"] >= int(cfg.get("lookup_daily_cap") or 0):
            return hit
        if e164 in _LOOKUP["inflight"]:
            return hit
        _LOOKUP["inflight"].add(e164); _LOOKUP["count"] += 1

    def work():
        res = _lookup_fetch(e164, cfg)
        res["ts"] = time.time(); res["number"] = e164
        _lookup_store(e164, res)
        with _LOOKUP["lock"]:
            _LOOKUP["inflight"].discard(e164)
        return res
    if background:
        threading.Thread(target=work, daemon=True).start()
        return {"pending": True}
    return work()


def lookup_status():
    cfg = load_cfg()
    return {"provider": cfg.get("lookup_provider") or "", "configured": bool(cfg.get("lookup_provider") and cfg.get("lookup_key")),
            "cached": len(_lookup_table()), "today": _LOOKUP["count"] if _LOOKUP["day"] == time.strftime("%Y-%m-%d") else 0, "cap": int(cfg.get("lookup_daily_cap") or 0)}


def high_cost_prefixes():
    return [re.sub(r"\D", "", x) for x in read_text_list(HIGH_COST_FILE) if re.sub(r"\D", "", x)]


def high_cost_npanxx():
    return set(re.sub(r"\D", "", x)[:6] for x in read_text_list(HIGH_COST_NPANXX_FILE) if len(re.sub(r"\D", "", x)) >= 6)


def destination_risk(dni_norm):
    """Facts about a called number: high-cost international prefix, traffic-pumping NPA-NXX."""
    out = {"high_cost": "", "pumping": False}
    if dni_norm.get("kind") == "intl":
        d = dni_norm["digits"]
        best = ""
        for p in high_cost_prefixes():
            if d.startswith(p) and len(p) > len(best):
                best = p
        out["high_cost"] = best
    elif dni_norm.get("kind") == "nanp":
        out["pumping"] = (dni_norm["npa"] + dni_norm["nxx"]) in high_cost_npanxx()
    return out


# ----------------------------------------------------------------------------- velocity (in-memory)
class _Velocity:
    def __init__(self):
        self.ani = collections.defaultdict(collections.deque)
        self.ip = collections.defaultdict(collections.deque)
        self.trunk = collections.defaultdict(collections.deque)
        self.trunk_anis = collections.defaultdict(dict)
        self.trunk_dest = collections.defaultdict(collections.deque)
        self.lock = threading.Lock()

    @staticmethod
    def _prune(dq, now, window):
        while dq and dq[0] < now - window:
            dq.popleft()

    def note(self, ani, ip, trunk_key, now, dest_key=""):
        with self.lock:
            if ani: self.ani[ani].append(now)
            if ip: self.ip[ip].append(now)
            if trunk_key:
                self.trunk[trunk_key].append(now)
                if ani: self.trunk_anis[trunk_key][ani] = now
                if dest_key: self.trunk_dest[trunk_key + "|" + dest_key].append(now)
            if len(self.trunk_dest) > 50000: self.trunk_dest.clear()
            if len(self.ani) > 50000: self.ani.clear()
            if len(self.ip) > 50000: self.ip.clear()

    def dest_count(self, trunk_key, dest_key, now):
        with self.lock:
            dq = self.trunk_dest.get(trunk_key + "|" + dest_key)
            if dq is None: return 0
            self._prune(dq, now, 3600)
            return len(dq)

    def counts(self, ani, ip, trunk_key, now):
        with self.lock:
            a = self.ani.get(ani) if ani else None
            if a is not None: self._prune(a, now, 300)
            i = self.ip.get(ip) if ip else None
            if i is not None: self._prune(i, now, 300)
            t = self.trunk.get(trunk_key) if trunk_key else None
            if t is not None: self._prune(t, now, 3600)
            cps = sum(1 for x in (t or ()) if x >= now - 1.0)
            ta = self.trunk_anis.get(trunk_key) if trunk_key else None
            distinct = 0
            if ta is not None:
                for k in [k for k, v in ta.items() if v < now - 3600]:
                    del ta[k]
                distinct = len(ta)
            return {"ani_5m": len(a) if a else 0, "ip_5m": len(i) if i else 0, "trunk_cps": cps,
                    "trunk_anis_1h": distinct, "trunk_1h": len(t) if t else 0}


VEL = _Velocity()


# ----------------------------------------------------------------------------- decision
def _trunk_cfg(company, trunk_id):
    c = _HOOKS["company_by_id"](company) if (company and "company_by_id" in _HOOKS) else None
    t = None
    if c:
        t = next((x for x in (c.get("customer_trunks") or []) if x.get("id") == trunk_id), None)
    cfg = load_cfg()
    mode = (t or {}).get("gate_mode") or cfg["default_mode"]
    if mode not in MODES: mode = cfg["default_mode"]
    threshold = int((t or {}).get("gate_threshold") or 0) or int(cfg["threshold"])
    cps = int((t or {}).get("cps_limit") or 0) or int(cfg["cps"])
    return {"company": c, "trunk": t, "mode": mode, "threshold": threshold, "cps": cps, "cfg": cfg}


def _in_ranges(digits10, ranges):
    d = digits10
    for r in ranges or []:
        r = re.sub(r"\D", "", str(r))
        if len(r) == 11 and r[0] == "1": r = r[1:]
        if r and d.startswith(r):
            return True
    return False



# --------------------------------------------------------------------------- structured-decision model
# Optional. Disabled unless gate.json sets model_enabled=1 and model_url. Sends only the structured
# features the rule engine already computed (never raw audio or transcripts). Hard wall-clock bound;
# any failure returns an error verdict and the deterministic decision stands (fail-open).
_MODEL_SCHEMA = {
    "action": {"type": "enum", "values": ["allow", "flag", "decline"],
               "question": "Allow, flag for review, or decline this pre-answer VoIP call as fraud / illegal robocall?"},
    "score": {"type": "int", "min": 0, "max": 100, "question": "Risk 0-100 (100 = certain fraud / illegal robocall)."},
    "reason": {"type": "string", "question": "Short reason for the verdict."},
    "confidence": {"type": "float", "min": 0, "max": 1, "question": "Confidence 0-1."},
}


def _model_features(ani, dni, risk, stir, sig_ip, media_ip, company, trunk, score, reasons, vel, ani_info):
    """Compact, typed feature snapshot for the model. Structured signals only."""
    return {
        "ani_e164": ani.get("e164") or "", "ani_kind": ani.get("kind") or "", "ani_flags": list(ani.get("flags") or []),
        "dni_e164": dni.get("e164") or "", "dni_kind": dni.get("kind") or "", "dni_country": dni.get("country") or "",
        "high_cost": risk.get("high_cost") or "", "traffic_pumping": bool(risk.get("pumping")),
        "sig_ip": sig_ip or "",
        "media_ip_mismatch": bool(media_ip and sig_ip and media_ip not in ("-", "0.0.0.0") and media_ip != sig_ip),
        "stir_status": stir.get("status") or "", "stir_attest": stir.get("attest") or "",
        "line_type": (ani_info or {}).get("line_type") or "", "carrier": (ani_info or {}).get("carrier") or "",
        "rule_score": int(score), "rule_reasons": [r["code"] for r in reasons],
        "ani_5m": vel.get("ani_5m"), "ip_5m": vel.get("ip_5m"),
        "trunk_anis_1h": vel.get("trunk_anis_1h"), "trunk_cps": vel.get("trunk_cps"),
        "company": company or "", "trunk": trunk or "",
    }


def model_decide(features, cfg):
    """POST features to the configured structured-decision endpoint. Returns a normalized verdict
    {action, score, reason, confidence, points} or {"error": ...}. Never raises."""
    url = str(cfg.get("model_url") or "").strip()
    if not url:
        return None
    try:
        body = json.dumps({"model": cfg.get("model_name") or "jev-1", "input": features, "schema": _MODEL_SCHEMA}).encode("utf-8")
    except (TypeError, ValueError) as e:
        return {"error": "encode: %s" % e}
    headers = {"Content-Type": "application/json"}
    key = str(cfg.get("model_key") or "").strip()
    if key:
        headers["Authorization"] = "Bearer " + key
    timeout = float(cfg.get("model_timeout") or 1.2)
    res = {}
    def run():
        try:
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=timeout) as r:
                res["raw"] = json.loads(r.read(65536).decode("utf-8", "replace"))
        except Exception as e:                      # noqa: BLE001 - fail-open, log nothing in hot path
            res["error"] = str(e)[:200]
    th = threading.Thread(target=run, daemon=True)
    th.start(); th.join(timeout + 0.25)
    if th.is_alive():
        return {"error": "timeout"}
    if "error" in res:
        return {"error": res["error"]}
    raw = res.get("raw")
    if not isinstance(raw, dict):
        return {"error": "bad response"}
    d = raw.get("decision") or raw.get("output") or raw.get("result") or raw
    if not isinstance(d, dict):
        return {"error": "bad decision"}
    action = str(d.get("action") or d.get("verdict") or "").strip().lower()
    reason = str(d.get("reason") or d.get("explanation") or "")[:120]
    try: mscore = float(d.get("score") if d.get("score") is not None else (d.get("risk") or 0))
    except (TypeError, ValueError): mscore = 0.0
    try: conf = float(d.get("confidence")) if d.get("confidence") is not None else None
    except (TypeError, ValueError): conf = None
    cap = max(0, int(cfg.get("model_max_points") or 40))
    if action in ("decline", "block", "reject", "deny", "fraud", "spam", "illegal", "high"):
        points = cap
    elif action in ("flag", "review", "suspect", "medium", "warn"):
        points = cap // 2
    elif not action and mscore:
        points = int(cap * min(1.0, max(0.0, mscore / 100.0)))
    else:
        points = 0
    return {"action": action or "allow", "score": mscore, "reason": reason, "confidence": conf, "points": points}


def decide(p, dry_run=False):
    """p: ani, dni, sig_ip, media_ip, identity, user_agent, company, trunk, uuid.  Returns the decision dict."""
    now = time.time()
    ani_raw, dni_raw = str(p.get("ani") or ""), str(p.get("dni") or "")
    sig_ip, media_ip = str(p.get("sig_ip") or ""), str(p.get("media_ip") or "")
    company, trunk = str(p.get("company") or "")[:32], str(p.get("trunk") or "")[:40]
    tc = _trunk_cfg(company, trunk)
    cfg = tc["cfg"]
    reasons, hard, allow = [], [], False
    code = 603

    def add(code_, points, detail=""):
        reasons.append({"code": code_, "points": points, "detail": detail, "label": REASONS.get(code_, code_)})

    ani = number_facts(ani_raw)
    dni = normalize_number(dni_raw)
    ani10 = ani["e164"][2:] if ani["kind"] == "nanp" else ani["digits"]
    dni10 = dni["e164"][2:] if dni["kind"] == "nanp" else dni["digits"]
    lists = _HOOKS["company_lists"](company) if (company and "company_lists" in _HOOKS) else {}

    # --- allow lists (win outright)
    if ani10 and (ani10 in (lists.get("allow_ani") or set()) or ani10 in {re.sub(r"\D", "", x)[-10:] for x in read_text_list(ALLOW_ANI_FILE)}):
        add("ALLOW_ANI", -100); allow = True
    if sig_ip and sig_ip in set(read_text_list(ALLOW_IP_FILE)):
        add("ALLOW_IP", -100); allow = True
    consent = lists.get("consent") or set()
    if ani10 and dni10 and ((ani10, dni10) in consent):
        add("CONSENT", -100); allow = True

    # --- hard blocks
    force_ani = {re.sub(r"\D", "", x)[-10:] for x in read_text_list(FORCE_ANI_FILE)} | set(lists.get("force_ani") or set())
    if ani10 and ani10 in force_ani:
        add("FORCE_ANI", 100); hard.append("FORCE_ANI")
    if sig_ip and sig_ip in set(read_text_list(FORCE_IP_FILE)):
        add("FORCE_IP", 100); hard.append("FORCE_IP")
    if ani10 and ani10 in dno_numbers():
        add("DNO", 100); hard.append("DNO")

    # --- velocity (counted before scoring so the current call is included)
    trunk_key = (company + "/" + trunk) if company else ("unassigned/" + sig_ip)
    dest_key = (dni["npa"] + dni["nxx"]) if dni["kind"] == "nanp" else ""
    if not dry_run:
        VEL.note(ani10 or ani_raw, sig_ip, trunk_key, now, dest_key)
    vel = VEL.counts(ani10 or ani_raw, sig_ip, trunk_key, now)
    if tc["cps"] and vel["trunk_cps"] > tc["cps"]:
        add("CPS_LIMIT", 100, "%d/s > %d/s" % (vel["trunk_cps"], tc["cps"])); hard.append("CPS_LIMIT"); code = 503
    if cfg["ani_5m"] and vel["ani_5m"] > int(cfg["ani_5m"]):
        add("ANI_VELOCITY", 20, "%d calls in 5 min" % vel["ani_5m"])
    if cfg["ip_5m"] and vel["ip_5m"] > int(cfg["ip_5m"]):
        add("IP_VELOCITY", 15, "%d calls in 5 min" % vel["ip_5m"])
    if cfg["anis_per_hour"] and vel["trunk_anis_1h"] > int(cfg["anis_per_hour"]):
        add("SNOWSHOE", 25, "%d distinct ANIs in 1 h" % vel["trunk_anis_1h"])

    # --- A number facts
    for fl in ani["flags"]:
        add(fl, {"ANI_INVALID": 30, "ANI_NPA_UNASSIGNED": 30, "ANI_NXX_UNALLOCATED": 30, "ANI_TOLLFREE": 15, "ANI_PREMIUM": 20}.get(fl, 10), ani["e164"] or ani_raw)
    if ani["kind"] == "nanp" and dni["kind"] == "nanp" and ani10 != dni10 and ani["npa"] + ani["nxx"] == dni["npa"] + dni["nxx"]:
        add("NEIGHBOR_SPOOF", 35, ani["npa"] + "-" + ani["nxx"])
    t = tc["trunk"] or {}
    if t.get("ani_ranges") and ani10 and not _in_ranges(ani10, t.get("ani_ranges")):
        add("ANI_NOT_DECLARED", 35, ani["e164"] or ani_raw)
    ftc = ftc_lookup(ani10) if ani["kind"] == "nanp" else None
    if ftc and ftc.get("complaints"):
        add("FTC_COMPLAINTS", 30 if ftc["complaints"] >= 3 else 15, "%d complaints, %d robocall, last %s" % (ftc["complaints"], ftc["robocalls"], ftc.get("last_seen") or "?"))
    v = verdict_lists()
    if ani10 and ani10 in v["anis"]:
        e = v["anis"][ani10]
        add("VERDICT_ANI", 60, "%d call(s), last %s, %s" % (e["count"], e["last"], e.get("category") or e.get("classification")))
    if sig_ip and sig_ip in v["ips"]:
        e = v["ips"][sig_ip]
        add("VERDICT_IP", 50, "%d call(s), last %s" % (e["count"], e["last"]))
    st = ani_stats().get(ani10) if ani10 else None
    if st and st["attempts"] >= 20:
        asr = st["connected"] * 100.0 / st["attempts"]
        acd = (st["billsec"] / st["connected"]) if st["connected"] else 0.0
        if asr < 20 and acd < 6:
            add("LOW_ASR_ACD", 20, "ASR %.0f%%, ACD %.1f s over %d attempts" % (asr, acd, st["attempts"]))
    if ani["kind"] == "intl" and vel["ani_5m"] >= 5 and st and st["attempts"] >= 5 and (st["connected"] == 0 or (st["billsec"] / max(1, st["connected"])) < 6):
        add("WANGIRI_PATTERN", 20, ani["e164"])

    # --- B number: destination risk (matters for the check API and customers' outbound protection)
    risk = destination_risk(dni)
    if risk["high_cost"]:
        add("DNI_HIGH_COST", 30, "+" + risk["high_cost"] + " " + (dni.get("country") or ""))
        if vel["ani_5m"] >= 5:
            add("IRSF_PATTERN", 25, "%d calls in 5 min to high-cost destinations" % vel["ani_5m"])
    if risk["pumping"]:
        add("DNI_TRAFFIC_PUMPING", 25, dest_key)
    if dest_key and cfg.get("dest_per_hour"):
        dc = VEL.dest_count(trunk_key, dest_key, now)
        if dc > int(cfg["dest_per_hour"]):
            add("ACCESS_STIMULATION", 20, "%d calls to %s in 1 h" % (dc, dest_key))
    # --- A number: carrier lookup (CNAM / line type), cached; a miss is fetched in the background for next time
    ani_info = number_lookup(ani10, allow_fetch=not dry_run, background=True) if ani["kind"] == "nanp" else None
    if ani_info and ani_info.get("pending"):
        add("LOOKUP_PENDING", 0)
    elif ani_info and not ani_info.get("error"):
        lt = str(ani_info.get("line_type") or "")
        if lt == "voip":
            add("LINE_TYPE_VOIP", 10, ani_info.get("carrier") or "")
        elif lt in ("landline", "fixed line", "toll-free") and not company:
            add("LINE_TYPE_MISMATCH", 15, "%s presented from an unknown VoIP source" % lt)
    dnc = lists.get("dnc") or set()
    if dni10 and dni10 in dnc and not ((ani10, dni10) in consent):
        add("DNC_NO_CONSENT", 25, dni["e164"] or dni_raw)

    # --- IP and transport
    if not company:
        add("UNKNOWN_SOURCE", 10, sig_ip)
    if media_ip and sig_ip and media_ip not in ("-", "0.0.0.0") and media_ip != sig_ip:
        add("MEDIA_IP_MISMATCH", 25, "media %s, signalling %s" % (media_ip, sig_ip))
    sc = scanner_ips().get(sig_ip)
    if sc:
        add("SCANNER_IP", 40, "%d probes, last %s" % (sc["count"], sc.get("last") or "?"))
    ua = str(p.get("user_agent") or "").lower()
    if ua:
        for pat in dialer_patterns():
            if pat and pat in ua:
                add("DIALER_AGENT", 10, ua[:60]); break

    # --- identity (bounded wait so the caller hears ringing promptly)
    stir = {"status": "", "attest": ""}
    identity = str(p.get("identity") or "")
    if not identity:
        add("STIR_MISSING", 15)
    elif "stir_verify" in _HOOKS:
        res = {}
        def run():
            try: res.update(_HOOKS["stir_verify"](identity, ani_raw, dni_raw, True) or {})
            except Exception as e: res["reason"] = str(e)
        th = threading.Thread(target=run, daemon=True); th.start(); th.join(float(cfg.get("stir_wait") or 1.5))
        if th.is_alive() or not res:
            add("STIR_PENDING", 0); stir["status"] = "pending"
        else:
            stir["attest"] = res.get("attest") or ""
            if res.get("verified"):
                stir["status"] = "passed"
            elif res.get("reachable") and not res.get("sig_valid"):
                stir["status"] = "failed"; add("STIR_FAILED", 40, res.get("reason") or "")
            elif res.get("tn_match") is False and res.get("sig_valid"):
                stir["status"] = "failed"; add("STIR_FAILED", 40, "signed numbers do not match the call")
            else:
                stir["status"] = "unverified"
            if stir["attest"] == "C": add("STIR_ATTEST_C", 10)
            elif stir["attest"] == "B": add("STIR_ATTEST_B", 5)

    score = sum(r["points"] for r in reasons)
    if allow:
        action = "allow"; score = max(0, score)
    elif hard or score >= tc["threshold"]:
        action = "decline"
    elif score >= int(cfg["flag_threshold"]):
        action = "flag"
    else:
        action = "allow"
    # --- optional structured-decision model (disabled unless configured). Escalates only; never
    #     downgrades a rule decline, and reaches "decline" only when model_can_decline is set.
    model = None
    if cfg.get("model_enabled") and cfg.get("model_url"):
        mode_m = cfg.get("model_mode") or "shadow"
        try:
            model = model_decide(_model_features(ani, dni, risk, stir, sig_ip, media_ip, company, trunk, score, reasons, vel, ani_info), cfg)
        except Exception as e:                      # noqa: BLE001 - fail-open
            model = {"error": str(e)[:200]}
        if model and not model.get("error") and mode_m in ("advisory", "active"):
            pts = 0
            if mode_m == "active" and not allow and not hard:
                pts = max(0, min(int(cfg.get("model_max_points") or 40), int(model.get("points") or 0)))
            conf = model.get("confidence")
            add("MODEL_RISK", pts, ("conf %.2f " % conf if isinstance(conf, (int, float)) else "") + (model.get("reason") or ""))
            if pts and not allow:
                score = sum(r["points"] for r in reasons)
                sev = {"allow": 0, "flag": 1, "decline": 2}
                cand = "allow"
                if score >= tc["threshold"]:
                    cand = "decline" if cfg.get("model_can_decline") else "flag"
                elif score >= int(cfg["flag_threshold"]):
                    cand = "flag"
                if sev[cand] > sev.get(action, 0):
                    action = cand
    enforced = (tc["mode"] == "enforce" and action == "decline")
    dec = {"ts": round(now, 3), "when": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(now)), "uuid": str(p.get("uuid") or "")[:64],
           "company": company, "trunk": trunk, "ani": ani_raw, "dni": dni_raw, "ani_e164": ani["e164"], "dni_e164": dni["e164"],
           "sig_ip": sig_ip, "media_ip": media_ip, "user_agent": str(p.get("user_agent") or "")[:80],
           "action": action, "enforced": enforced, "mode": tc["mode"], "score": score, "threshold": tc["threshold"],
           "code": code if action == "decline" else 0, "reasons": reasons, "stir": stir, "velocity": vel, "dry_run": bool(dry_run),
           "ani_info": {k: ani_info.get(k) for k in ("line_type", "carrier", "cnam")} if (ani_info and not ani_info.get("pending")) else None,
           "destination": {"country": dni.get("country") or "", "high_cost": risk["high_cost"], "pumping": risk["pumping"]},
           "model": model}
    if "company_label" in _HOOKS:
        dec["company_name"] = _HOOKS["company_label"](company) if company else "Unassigned"
    if "trunk_label" in _HOOKS:
        dec["trunk_name"] = _HOOKS["trunk_label"](company, trunk) if trunk else ""
    if not dry_run:
        log_decision(dec)
    return dec


def format_for_lua(dec):
    cfg = load_cfg()
    text = "Declined"
    if dec.get("code") == 503: text = "Service Unavailable"
    lines = ["action=%s" % dec["action"], "enforce=%d" % (1 if dec["enforced"] else 0), "score=%d" % dec["score"],
             "code=%d" % (dec.get("code") or 0), "text=%s" % text,
             "reasons=%s" % ",".join(r["code"] for r in dec["reasons"]),
             "mode=%s" % dec["mode"], "contact=%s" % (cfg.get("dispute_contact") or "")]
    return "\n".join(lines) + "\n"


# ----------------------------------------------------------------------------- decision log
_LOG_LOCK = threading.Lock()


def log_decision(dec):
    try:
        os.makedirs(DECISIONS_DIR, exist_ok=True)
        path = os.path.join(DECISIONS_DIR, time.strftime("%Y-%m", time.gmtime(dec["ts"])) + ".jsonl")
        slim = dict(dec); slim.pop("dry_run", None)
        with _LOG_LOCK:
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(slim, separators=(",", ":")) + "\n")
    except OSError as e:
        print("gate log write failed: %s" % e, flush=True)


def _months_between(date_from, date_to):
    a = datetime.date.fromisoformat(date_from); b = datetime.date.fromisoformat(date_to)
    out, cur = [], datetime.date(a.year, a.month, 1)
    while cur <= b:
        out.append(cur.strftime("%Y-%m"))
        cur = datetime.date(cur.year + (cur.month // 12), (cur.month % 12) + 1, 1)
    return out


_DEC_FILES = {}   # path -> {"size": int, "rows": [dict]}  append-only files are parsed incrementally


def _decision_rows(path):
    """All decisions in one monthly file, parsed once and extended as the file grows."""
    try:
        size = os.stat(path).st_size
    except OSError:
        return []
    with _LOCK:
        ent = _DEC_FILES.get(path)
    if ent and ent["size"] == size:
        return ent["rows"]
    rows = list(ent["rows"]) if (ent and size > ent["size"]) else []
    start = ent["size"] if (ent and size > ent["size"]) else 0
    try:
        with open(path, "rb") as f:
            f.seek(start)
            data = f.read()
        end = data.rfind(b"\n")
        if end < 0:
            return rows
        for line in data[:end].split(b"\n"):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except ValueError:
                continue
        parsed_size = start + end + 1
    except OSError:
        return rows
    with _LOCK:
        _DEC_FILES[path] = {"size": parsed_size, "rows": rows}
        if len(_DEC_FILES) > 4:
            for k in sorted(_DEC_FILES)[:-4]:
                _DEC_FILES.pop(k, None)
    return rows


def read_decisions(date_from="", date_to="", company="", trunk="", action="", q="", limit=500):
    today = time.strftime("%Y-%m-%d", time.gmtime())
    date_from = date_from or today; date_to = date_to or today
    try:
        months = _months_between(date_from, date_to)
    except ValueError:
        return {"ok": False, "error": "bad date"}
    rows, counts, reason_counts, n_total = [], {"allow": 0, "flag": 0, "decline": 0, "enforced": 0}, {}, 0
    q = (q or "").strip().lower()
    for m in months:
        path = os.path.join(DECISIONS_DIR, m + ".jsonl")
        try:
            if True:
                for d in _decision_rows(path):
                    day = str(d.get("when") or "")[:10]
                    if day < date_from or day > date_to:
                        continue
                    if company == "unassigned":
                        if d.get("company"): continue
                    elif company and d.get("company") != company:
                        continue
                    if trunk == "unassigned":
                        if d.get("trunk"): continue
                    elif trunk and d.get("trunk") != trunk:
                        continue
                    if action and d.get("action") != action:
                        continue
                    if q and q not in " ".join(str(d.get(k) or "") for k in ("ani", "dni", "sig_ip", "media_ip", "user_agent")).lower() \
                            and not any(q in (r.get("code") or "").lower() for r in d.get("reasons") or []):
                        continue
                    n_total += 1
                    counts[d.get("action") or "allow"] = counts.get(d.get("action") or "allow", 0) + 1
                    if d.get("enforced"): counts["enforced"] += 1
                    for r in d.get("reasons") or []:
                        if r.get("points", 0) > 0:
                            reason_counts[r["code"]] = reason_counts.get(r["code"], 0) + 1
                    rows.append(d)
        except OSError:
            continue
    rows.sort(key=lambda d: -float(d.get("ts") or 0))
    top = [{"code": k, "label": REASONS.get(k, k), "count": v} for k, v in sorted(reason_counts.items(), key=lambda kv: -kv[1])[:12]]
    return {"ok": True, "range": {"from": date_from, "to": date_to}, "total": n_total, "counts": counts, "top_reasons": top,
            "rows": rows[:max(1, min(int(limit or 500), 2000))], "reasons": REASONS, "settings": load_cfg()}


def decision_for_uuid(uuid_):
    """Look up a logged decision for a call by its UUID (used by call reports and traceback packets)."""
    if not uuid_:
        return None
    try:
        files = sorted(os.listdir(DECISIONS_DIR), reverse=True)[:3]
    except OSError:
        return None
    for name in files:
        try:
            with open(os.path.join(DECISIONS_DIR, name), encoding="utf-8") as f:
                for line in f:
                    if uuid_ in line:
                        try:
                            d = json.loads(line)
                            if d.get("uuid") == uuid_: return d
                        except ValueError:
                            continue
        except OSError:
            continue
    return None


FRAUD_TYPES = [
    ("spoofing", "Caller ID spoofing", ("STIR_FAILED", "NEIGHBOR_SPOOF", "ANI_INVALID", "ANI_NPA_UNASSIGNED", "ANI_NXX_UNALLOCATED", "ANI_NOT_DECLARED", "LINE_TYPE_MISMATCH", "DNO")),
    ("robocall_burst", "Robocall bursts", ("ANI_VELOCITY", "IP_VELOCITY", "SNOWSHOE", "LOW_ASR_ACD", "CPS_LIMIT")),
    ("irsf_wangiri", "IRSF and Wangiri", ("DNI_HIGH_COST", "IRSF_PATTERN", "WANGIRI_PATTERN")),
    ("toll_fraud", "Toll fraud and PBX probing", ("SCANNER_IP", "DIALER_AGENT", "UNKNOWN_SOURCE")),
    ("traffic_pumping", "Traffic pumping", ("DNI_TRAFFIC_PUMPING", "ACCESS_STIMULATION")),
    ("reputation", "Known-bad reputation", ("FTC_COMPLAINTS", "VERDICT_ANI", "VERDICT_IP", "FORCE_ANI", "FORCE_IP")),
    ("tcpa", "TCPA and consent", ("DNC_NO_CONSENT",)),
    ("routing", "Unusual routing", ("MEDIA_IP_MISMATCH", "STIR_ATTEST_C", "STIR_MISSING")),
]


def fraud_types(date_from, date_to, company="", trunk=""):
    """Decision reason codes in range grouped into the fraud types the market talks about (calls counted once per type)."""
    r = read_decisions(date_from, date_to, company, trunk, limit=2000)
    out = [{"key": k, "label": lbl, "codes": list(codes), "calls": 0, "declined": 0} for k, lbl, codes in FRAUD_TYPES]
    idx = {}
    for t in out:
        for c in t["codes"]: idx[c] = t
    for d in r.get("rows") or []:
        hit = set()
        for reason in d.get("reasons") or []:
            t = idx.get(reason.get("code"))
            if t and reason.get("points", 0) > 0 and t["key"] not in hit:
                hit.add(t["key"]); t["calls"] += 1
                if d.get("action") == "decline": t["declined"] += 1
    return {"range": r.get("range"), "evaluated": r.get("total", 0), "types": out}


def summary(date_from, date_to, company="", trunk=""):
    r = read_decisions(date_from, date_to, company, trunk, limit=1)
    if not r.get("ok"):
        return {"total": 0, "counts": {}, "top_reasons": [], "fraud_types": []}
    return {"total": r["total"], "counts": r["counts"], "top_reasons": r["top_reasons"][:6], "fraud_types": fraud_types(date_from, date_to, company, trunk)["types"]}


# ----------------------------------------------------------------------------- disputes (safe harbor) and RMD statement
def log_dispute(entry):
    entry = dict(entry); entry["ts"] = time.time(); entry["when"] = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    kind, value = entry.get("kind"), str(entry.get("value") or "").strip()
    if kind == "ani":
        d = re.sub(r"\D", "", value)
        if len(d) == 11 and d[0] == "1": d = d[1:]
        if not d: return {"ok": False, "error": "number required"}
        cur = read_text_file(ALLOW_ANI_FILE)
        if d not in {re.sub(r"\D", "", x)[-10:] for x in read_text_list(ALLOW_ANI_FILE)}:
            write_text_list(ALLOW_ANI_FILE, cur.rstrip("\n") + "\n" + d + "  # dispute " + entry["when"][:10])
        entry["value"] = d
    elif kind == "ip":
        try: ipaddress.ip_address(value)
        except ValueError: return {"ok": False, "error": "valid IP required"}
        cur = read_text_file(ALLOW_IP_FILE)
        if value not in set(read_text_list(ALLOW_IP_FILE)):
            write_text_list(ALLOW_IP_FILE, cur.rstrip("\n") + "\n" + value + "  # dispute " + entry["when"][:10])
    else:
        return {"ok": False, "error": "kind must be ani or ip"}
    with _LOG_LOCK:
        with open(DISPUTES_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")
    return {"ok": True, "dispute": entry}


def read_disputes(limit=200):
    out = []
    try:
        with open(DISPUTES_FILE, encoding="utf-8") as f:
            for line in f:
                try: out.append(json.loads(line))
                except ValueError: continue
    except OSError:
        pass
    return out[-limit:][::-1]


def rmd_statement(company="", days=30):
    """Robocall Mitigation Database program description, generated from live configuration and the decision log."""
    cfg = load_cfg()
    today = datetime.date.today()
    d_from = (today - datetime.timedelta(days=days - 1)).isoformat()
    stats = read_decisions(d_from, today.isoformat(), company, "", limit=1)
    counts = stats.get("counts") or {}
    disputes = read_disputes(10000)
    v = verdict_lists()
    lines = [
        "ROBOCALL MITIGATION PROGRAM DESCRIPTION",
        "Generated %s UTC from the live configuration of the 3366 honeypot platform%s." % (time.strftime("%Y-%m-%d %H:%M"), (" for company " + company) if company else ""),
        "",
        "1. SCOPE",
        "All SIP INVITEs reaching the platform's honeypot prefix are attributed to a customer trunk by source IP and dialed prefix,",
        "scored before answer, recorded after answer and classified from the audio (ITG campaign taxonomy).",
        "",
        "2. KNOW YOUR CUSTOMER",
        "Each customer trunk is defined by source IPs, an optional inbound prefix, an upstream carrier / OCN and the ANI ranges the",
        "customer is authorised to present (proof of number possession). Calls presenting numbers outside the declared ranges are scored.",
        "",
        "3. PRE-ANSWER ANALYTICS (reasonable analytics)",
        "Stage 0 trunk admission: source IP allowlist per trunk, calls-per-second limit (%s/s default, 0 = none)." % cfg.get("cps"),
        "Stage 1 hard blocks: Do Not Originate list (%d numbers), block lists (%d numbers, %d IPs)." % (len(dno_numbers()), len(read_text_list(FORCE_ANI_FILE)), len(read_text_list(FORCE_IP_FILE))),
        "Stage 2 identity: STIR/SHAKEN signature verification against the signer's certificate, attestation level, TN match%s." % (", chain validation against the STI-PA CA list" if os.path.exists("/opt/voip/companies/sti_ca_list.pem") else ""),
        "Stage 3 scoring: invalid or unassigned calling numbers (NANPA data), neighbor spoofing, toll-free and premium ANI, FTC Do Not Call",
        "complaint feed (nightly), the platform's own audio verdicts (%d numbers, %d IPs in the last %d days), velocity (per number, per IP," % (len(v.get("anis") or {}), len(v.get("ips") or {}), v.get("days", 30)),
        "distinct numbers per trunk per hour), answer-seizure ratio and average call duration, media / signalling IP mismatch, SIP scanner",
        "IPs (%d observed), dialer User-Agents, high-cost international destinations, access-stimulation NPA-NXX, carrier lookup (%s)." % (len(scanner_ips()), cfg.get("lookup_provider") or "not configured"),
        "Decline threshold %s points, flag threshold %s points. Default mode: %s." % (cfg.get("threshold"), cfg.get("flag_threshold"), cfg.get("default_mode")),
        "",
        "4. BLOCKING AND LOGGING",
        "Trunks in enforce mode reject declines with SIP 603 Decline (503 for CPS). Every decision, enforced or not, is written to an",
        "append-only monthly log with the calling and called numbers, IPs, score, reason codes and feature values.",
        "Last %d days%s: %d calls evaluated, %d allowed, %d flagged, %d would decline, %d declined and enforced." % (days, (" (" + company + ")") if company else "", stats.get("total", 0), counts.get("allow", 0), counts.get("flag", 0), (counts.get("decline", 0) - counts.get("enforced", 0)), counts.get("enforced", 0)),
        "",
        "5. POST-CALL ANALYSIS AND FEEDBACK",
        "Recordings are transcribed and classified (fraud, illegal robocall, unwanted, review, no finding) with pre-recorded message, PII and",
        "content-safety detection. Fraud and illegal-robocall verdicts feed the pre-answer score for the following %d days." % v.get("days", 30),
        "",
        "6. TRACEBACK COOPERATION",
        "For any call a traceback packet is produced on demand: audio capture, SIP facts, STIR result, signing certificate, customer trunk,",
        "declared upstream carrier, analysis, transcript and the pre-answer decision.",
        "",
        "7. DISPUTE RESOLUTION (safe harbor)",
        "Point of contact for blocked-call disputes: %s" % (cfg.get("dispute_contact") or "NOT SET - configure in Gate settings"),
        "Enforced declines carry an X-Dispute-Contact header. A verified dispute allow-lists the number or IP and is logged; %d disputes on record." % len(disputes),
        "",
        "8. DATA RETENTION",
        "Call artefacts are retained %s." % (("for %d days" % cfg["retention_days"]) if int(cfg.get("retention_days") or 0) > 0 else "indefinitely (retention not set)"),
    ]
    return "\n".join(lines) + "\n"
