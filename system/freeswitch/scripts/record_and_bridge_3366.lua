-- record_and_bridge_3366.lua
-- Spam-only admission gate removed: all valid 3366 calls continue to recording and bridging.
-- USA prefix 3366: answer, record the A-leg, bridge to the configured vendor.
-- Vendor endpoint + tech-prefix are read live from plain files so they can be
-- changed from the frontend without a reloadxml or FreeSWITCH restart.
-- Recording filename encodes: date, time, ANI (caller), DNI (dialed), uuid.

local VENDOR_FILE = "/opt/voip/vendor_3366.conf"
local PREFIX_FILE = "/opt/voip/vendor_3366_prefix.conf"
local REC_DIR     = "/opt/voip/recordings"

local function read_first_line(path)
    local f = io.open(path, "r")
    if not f then return nil end
    for line in f:lines() do
        line = line:gsub("^%s+", ""):gsub("%s+$", "")
        if line ~= "" and line:sub(1, 1) ~= "#" then
            f:close()
            return line
        end
    end
    f:close()
    return nil
end

local function read_vendor() return read_first_line(VENDOR_FILE) end
local function read_prefix() return read_first_line(PREFIX_FILE) or "" end

local function digits(s)
    if not s then return "" end
    return (s:gsub("[^%d]", ""))
end

-- DNI: the dialed number (digits after the 3366 prefix)
local dest = session:getVariable("destination_number_ori")
if not dest or dest == "" then
    dest = session:getVariable("destination_number") or "unknown"
end
-- Strip the 3366 routing prefix if it survived (fallback path / alt dialplan),
-- so both the vendor bridge and the DNI display use the real dialed number.
dest = dest:gsub("^3366", "", 1)
if dest == "" then dest = "unknown" end
local dialed_raw = dest  -- as received (after 3366), before any customer-trunk prefix strip

-- ANI: the caller's number
local ani = session:getVariable("caller_id_number")
if not ani or ani == "" then
    ani = session:getVariable("sip_from_user") or ""
end

local dni_s = digits(dest); if dni_s == "" then dni_s = "unknown" end
local ani_s = digits(ani);  if ani_s == "" then ani_s = "unknown" end

local uuid    = session:get_uuid()
local ts      = os.date("%Y%m%d_%H%M%S")
local recfile = REC_DIR .. "/3366_" .. ts .. "_" .. ani_s .. "_" .. dni_s .. "_" .. uuid .. ".wav"
local vendor  = read_vendor()
local prefix  = read_prefix()

local meta_path = recfile:gsub("%.wav$", ".meta")
local sig_ip = session:getVariable("sip_received_ip") or
               session:getVariable("network_addr") or
               session:getVariable("sip_network_ip") or ""
-- Only allow an IP-literal value into outbound SIP headers.
if not sig_ip:match("^[0-9A-Fa-f:.]+$") then sig_ip = "" end
local media_ip = session:getVariable("remote_media_ip") or ""
-- remote_media_ip comes from the inbound SDP and is the carrier's negotiated
-- RTP endpoint. Only forward a literal IP; never copy arbitrary SDP text into
-- a SIP header. Fall back to the signaling peer when no media IP is available.
if not media_ip:match("^[0-9A-Fa-f:.]+$") then media_ip = "" end
if media_ip == "" or media_ip == "0.0.0.0" then media_ip = sig_ip end

-- ---------------------------------------------------------------------------
-- Per-company routing (panel-generated /opt/voip/companies/routing.tsv):
--   #ENFORCE_ACL=0|1
--   cidr<TAB>company_id<TAB>vendor_ip<TAB>tech_prefix<TAB>inbound_prefix<TAB>customer_trunk<TAB>vendor_trunk
-- Rows are ordered longest inbound prefix first. A row matches when the source
-- IP is inside cidr and the dialed number (after 3366) starts with the inbound
-- prefix (empty prefix = any). The inbound prefix is stripped before bridging.
-- A matching customer trunk overrides vendor/tech prefix with its vendor trunk.
-- With ENFORCE_ACL=1, calls from unlisted IPv4 sources are answered with 403.
-- ---------------------------------------------------------------------------
local function ipv4_to_int(ip)
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return nil end
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    if a > 255 or b > 255 or c > 255 or d > 255 then return nil end
    return ((a * 256 + b) * 256 + c) * 256 + d
end
local function ip_in_cidr(ip, cidr)
    local base, bits = cidr:match("^([%d%.]+)/(%d+)$")
    if not base then base, bits = cidr, "32" end
    local ipn, basen, nbits = ipv4_to_int(ip), ipv4_to_int(base), tonumber(bits)
    if not ipn or not basen or not nbits or nbits < 0 or nbits > 32 then return false end
    if nbits == 0 then return true end
    local shift = 2 ^ (32 - nbits)
    return math.floor(ipn / shift) == math.floor(basen / shift)
end
local company_id, customer_trunk, vendor_trunk = "", "", ""
do
    local rf = io.open("/opt/voip/companies/routing.tsv", "r")
    if rf then
        local enforce = false
        for line in rf:lines() do
            if line:sub(1, 13) == "#ENFORCE_ACL=" then
                enforce = (line:sub(14, 14) == "1")
            elseif line ~= "" and line:sub(1, 1) ~= "#" then
                local cidr, cid, v, p, inp, ct, vt = line:match("^([^\t]+)\t([^\t]*)\t([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)")
                inp = inp or ""
                if cidr and sig_ip ~= "" and ip_in_cidr(sig_ip, cidr)
                   and (inp == "" or dest:sub(1, #inp) == inp) then
                    company_id = cid or ""
                    customer_trunk = ct or ""
                    vendor_trunk = vt or ""
                    if v and v ~= "" then
                        vendor = v
                        prefix = p or ""
                    end
                    if inp ~= "" then
                        -- strip the customer trunk's inbound prefix; rename the capture to the real DNI
                        dest = dest:sub(#inp + 1)
                        if dest == "" then dest = "unknown" end
                        dni_s = digits(dest); if dni_s == "" then dni_s = "unknown" end
                        recfile = REC_DIR .. "/3366_" .. ts .. "_" .. ani_s .. "_" .. dni_s .. "_" .. uuid .. ".wav"
                        meta_path = recfile:gsub("%.wav$", ".meta")
                    end
                    break
                end
            end
        end
        rf:close()
        if enforce and company_id == "" then
            session:consoleLog("warning", "[3366] company ACL: rejecting unknown source " .. sig_ip .. "\n")
            session:execute("respond", "403 Forbidden")
            return
        end
    end
end
-- Prefer the media address ADVERTISED in the inbound SDP c= line over the
-- latched RTP source (remote_media_ip). Upstream advertises its real media IP
-- (e.g. 149.210.145.184) in c=, but FS latches remote_media_ip to the RTP/
-- signaling source (e.g. -- inside the vendor's own /24 -> 482).
local remote_sdp = session:getVariable("switch_r_sdp") or ""
local sdp_c_ip = remote_sdp:match("c=IN IP4%s+([0-9%.]+)") or ""
if sdp_c_ip:match("^[0-9%.]+$") and sdp_c_ip ~= "0.0.0.0" then media_ip = sdp_c_ip end
local original_media_ip = media_ip
local identity_header = session:getVariable("sip_h_Identity") or
                        session:getVariable("sip_h_identity") or
                        session:getVariable("sip_identity") or ""
identity_header = identity_header:gsub("[\r\n]", "")
local pai_header = session:getVariable("sip_h_P-Asserted-Identity") or ""
pai_header = pai_header:gsub("[\r\n]", "")
local verstat = session:getVariable("sip_verstat") or
                session:getVariable("verstat") or
                session:getVariable("sip_h_Verstat") or ""
if verstat == "" then
    verstat = pai_header:match("[vV][eE][rR][sS][tT][aA][tT]=([^;>,%s]+)") or ""
end
local user_agent = (session:getVariable("sip_user_agent") or ""):gsub("[\r\n]", "")
local via_host = (session:getVariable("sip_via_host") or ""):gsub("[\r\n]", "")

local function json_escape(value)
    local text = tostring(value or "")
    return (text:gsub("\\", "\\\\"):gsub('"', '\\"'):gsub("\r", "\\r"):gsub("\n", "\\n"))
end

local GATE = {action = "", score = 0, reasons = "", enforced = false, mode = "", answered = 0}
local function write_meta(sip_code, sip_reason, sip_state, hangup_cause, originate_disposition, connected)
    local connected_json = "null"
    if connected ~= nil then connected_json = connected and "true" or "false" end
    -- FreeSWITCH only publishes answer_epoch at hangup, so the answer time is taken in-script.
    local answer_epoch = GATE.answered
    local end_epoch = os.time()
    local billsec = 0
    if answer_epoch > 0 and sip_state ~= "pending" then billsec = math.max(0, end_epoch - answer_epoch) end
    local mf = io.open(meta_path, "w")
    if not mf then return end
    mf:write(string.format(
        '{"media_ip":"%s","sig_ip":"%s","ani":"%s","dni":"%s","sip_code":"%s","sip_reason":"%s","sip_state":"%s","hangup_cause":"%s","originate_disposition":"%s","connected":%s,"identity_header":"%s","verstat":"%s","pai_header":"%s","user_agent":"%s","via_host":"%s","company":"%s","customer_trunk":"%s","vendor_trunk":"%s","dialed":"%s","gate":{"action":"%s","score":%d,"reasons":"%s","enforced":%s,"mode":"%s"},"answer_epoch":%d,"end_epoch":%d,"billsec":%d}',
        json_escape(media_ip), json_escape(sig_ip), json_escape(ani_s), json_escape(dni_s),
        json_escape(sip_code), json_escape(sip_reason), json_escape(sip_state),
        json_escape(hangup_cause), json_escape(originate_disposition), connected_json,
        json_escape(identity_header), json_escape(verstat), json_escape(pai_header),
        json_escape(user_agent), json_escape(via_host), json_escape(company_id),
        json_escape(customer_trunk), json_escape(vendor_trunk), json_escape(digits(dialed_raw)),
        json_escape(GATE.action), GATE.score, json_escape(GATE.reasons), GATE.enforced and "true" or "false", json_escape(GATE.mode),
        answer_epoch, end_epoch, billsec))
    mf:close()
end

local SIP_REASONS = {
    ["200"] = "Connected", ["404"] = "Not found", ["408"] = "Request timeout",
    ["480"] = "Temporarily unavailable", ["486"] = "Busy", ["487"] = "Caller cancelled",
    ["488"] = "Not acceptable", ["500"] = "Server error", ["502"] = "Bad gateway",
    ["503"] = "Temporary failure", ["603"] = "Declined"
}
local DISPOSITION_TO_SIP = {
    SUCCESS = "200", CALL_REJECTED = "603", NORMAL_TEMPORARY_FAILURE = "503",
    USER_BUSY = "486", NO_ANSWER = "480", NO_USER_RESPONSE = "408",
    ORIGINATOR_CANCEL = "487", UNALLOCATED_NUMBER = "404",
    DESTINATION_OUT_OF_ORDER = "502", NORMAL_CIRCUIT_CONGESTION = "503",
    INCOMPATIBLE_DESTINATION = "488", RECOVERY_ON_TIMER_EXPIRE = "408"
}

local function persist_bridge_result()
    local disposition = session:getVariable("originate_disposition") or ""
    local bridge_cause = session:getVariable("bridge_hangup_cause") or ""
    local proto_cause = session:getVariable("last_bridge_proto_specific_hangup_cause") or
                        session:getVariable("proto_specific_hangup_cause") or ""
    local sip_code = proto_cause:match("[sS][iI][pP][%s:/]+(%d%d%d)") or DISPOSITION_TO_SIP[disposition] or ""
    local connected = disposition == "SUCCESS"
    if connected then sip_code = "200" end
    local sip_reason = SIP_REASONS[sip_code] or (sip_code ~= "" and "SIP response" or "Call ended")
    local hangup_cause = bridge_cause ~= "" and bridge_cause or disposition
    write_meta(sip_code, sip_reason, connected and "connected" or "failed", hangup_cause, disposition, connected)
end

-- (2026-10-02) TERM-SPOOF pool block removed: no random pool IP anywhere.
-- ---------------------------------------------------------------------------
-- Pre-answer decision: ask the panel's gate engine (voip_gate.py) with the A number,
-- B number, IPs, Identity header and trunk. Fails open: no reply within the timeout
-- means allow. In enforce mode a decline is answered with SIP 603 (503 for CPS).
-- ---------------------------------------------------------------------------
local gate_action, gate_score, gate_reasons, gate_enforced, gate_mode = "", 0, "", false, ""
do
    -- FreeSWITCH cannot fork a shell from Lua here (os.execute/io.popen return nothing), so the
    -- request goes through mod_curl, which is loaded from modules.conf.xml.
    local function urlencode(v)
        return (tostring(v or ""):gsub("[^%w%-_%.~]", function(c) return string.format("%%%02X", string.byte(c)) end))
    end
    local body = "ani=" .. urlencode(ani_s) .. "&dni=" .. urlencode(dni_s) .. "&sig_ip=" .. urlencode(sig_ip)
        .. "&media_ip=" .. urlencode(media_ip) .. "&user_agent=" .. urlencode(user_agent) .. "&company=" .. urlencode(company_id)
        .. "&trunk=" .. urlencode(customer_trunk) .. "&uuid=" .. urlencode(uuid) .. "&identity=" .. urlencode(identity_header)
    local reply = ""
    do
        local ok, res = pcall(function()
            return freeswitch.API():execute("system", "curl -s -m 4 -X POST --data '" .. body .. "' http://127.0.0.1:8080/api/gate")
        end)
        if ok and type(res) == "string" then reply = res end
    end
    if reply:find("^action=") then
        local kv = {}
        for line in reply:gmatch("[^\n]+") do
            local k, v = line:match("^([%w_]+)=(.*)$")
            if k then kv[k] = v end
        end
        gate_action = kv.action or ""
        gate_score = tonumber(kv.score) or 0
        gate_reasons = kv.reasons or ""
        gate_mode = kv.mode or ""
        gate_enforced = (kv.enforce == "1")
        GATE.action, GATE.score, GATE.reasons, GATE.enforced, GATE.mode = gate_action, gate_score, gate_reasons, gate_enforced, gate_mode
        if gate_action ~= "" then
            session:consoleLog("info", "[3366] gate action=" .. gate_action .. " score=" .. tostring(gate_score) .. " mode=" .. gate_mode .. " reasons=" .. gate_reasons .. "\n")
        end
        if gate_action == "decline" and gate_enforced then
            local code = kv.code or "603"
            if code ~= "603" and code ~= "503" and code ~= "403" then code = "603" end
            local text = kv.text or "Declined"
            write_meta(code, "Declined by gate (" .. gate_reasons .. ")", "declined", "CALL_REJECTED", "GATE_DECLINE", false)
            session:consoleLog("warning", "[3366] gate DECLINE " .. code .. " ani=" .. ani_s .. " ip=" .. sig_ip .. " reasons=" .. gate_reasons .. "\n")
            if kv.contact and kv.contact ~= "" then
                session:execute("set", "sip_bye_h_X-Dispute-Contact=" .. kv.contact)
            end
            session:execute("respond", code .. " " .. text)
            return
        end
    end
end

session:answer()
GATE.answered = os.time()
-- Write a pending sidecar immediately, then replace it with the final SIP result
-- as soon as the vendor bridge returns.
write_meta("", "In progress", "pending", "", "", nil)
-- A-leg only: record just the read stream (inbound caller audio).
-- read = audio received from the caller on this leg; write (far-end/B-leg
-- vendor audio) is intentionally excluded.
session:execute("set", "RECORD_STEREO=false")
session:execute("set", "RECORD_READ_ONLY=true")
session:execute("record_session", recfile)

if vendor and vendor ~= "" then
    -- vendor authorizes by source IP + technical prefix (no digest auth),
    -- keyed to 139.64.178.194:5060 -> must egress from the internal profile
    -- (:5060). Sourcing from external (:5080) gets 401. Prepend the
    -- tech-prefix to the dialed number for the outbound leg only.
    -- Advertise the inbound carrier's negotiated media IP in the OUTBOUND SDP
    -- (c=/o= line) so the downstream vendor's CDR records the originating
    -- carrier's media IP instead of this FreeSWITCH box. FS still anchors RTP
    -- (A-leg recording stays intact); only the *advertised* address changes.
    -- The real packet source stays 139.64.178.194, so return media relies on the
    -- vendor doing symmetric RTP (latching) -- VOS3000/most carriers do.
    -- Rotating US media-IP pool (snapshot of OPS dr_gateways US gateways).
    -- Hides box 139.64.178.194: advertise a random plausible US IP in SDP c=/o=.
    -- Vendor validates c= by geo/reputation (US ok, foreign -> 408); latches media to wire source.
    -- TRANSPARENT MEDIA IP (2026-10-02): advertise in the vendor-leg SDP c=/o=
    -- exactly the media IP the customer advertised to us (inbound SDP c=).
    -- No random pool, no box IP. FS still anchors RTP for the A-leg recording.
    -- MEDIA ANCHORING (2026-10-02): the switch advertises its OWN RTP IP
    -- (139.64.178.194) toward the vendor so audio relays through the box and
    -- flows both ways; the A-leg recording also stays intact. The customer's
    -- originating media IP is still conveyed to the vendor, but as informational
    -- X-Orig headers only (set below), never as the RTP c=/o= address -- a c=
    -- the box does not listen on sends the vendor's audio into a black hole.
    local adv = ""
    local dialstr = adv .. "sofia/internal/" .. prefix .. dni_s .. "@" .. vendor
    session:execute("set", "hangup_after_bridge=false")
    session:execute("set", "continue_on_fail=true")
    -- RESTORE 2026-09-02: session rtp_adv_audio_ip disabled; keep SDP c= = box IP  -- FRAUDSPOOF: advertise customer media IP in B-leg SDP
    if original_media_ip ~= "" then
        -- Populate the vendor-supported headers with the inbound carrier's
        -- negotiated RTP address, not this FreeSWITCH box or the SIP peer.
        -- The packet-level RTP source remains FreeSWITCH while recording is on.
        session:execute("bridge_export", "sip_h_X-Original-Source-IP=" .. original_media_ip)
        session:execute("bridge_export", "sip_h_X-Orig-IP=" .. original_media_ip)
    end
    -- Preserve an inbound STIR/SHAKEN PASSporT for the downstream provider.
    -- Presence alone is never treated as successful verification.
    if identity_header ~= "" then
        session:execute("bridge_export", "sip_h_identity=" .. identity_header)
    end
    session:consoleLog("info", "[3366] ani=" .. ani_s .. " dni=" .. dni_s .. " prefix=" .. prefix .. " -> " .. dialstr .. " rec=" .. recfile .. "\n")
    session:execute("bridge", dialstr)
    persist_bridge_result()
else
    session:consoleLog("info", "[3366] no vendor for ani=" .. ani_s .. " ip=" .. sig_ip .. " -> honeypot IVR, recording " .. recfile .. "\n")
    if session:ready() then session:execute("playback", "/usr/local/freeswitch/sounds/start3366.wav") end
    if session:ready() then session:execute("say", "en name_spelled iterated FEMININE " .. dni_s) end
    if session:ready() then session:execute("playback", "/usr/local/freeswitch/sounds/end3366.wav") end
    if session:ready() then session:execute("sleep", "180000") end
    write_meta("200", "Connected (honeypot IVR, no vendor)", "answered", "NORMAL_CLEARING", "SUCCESS", true)
end

if session:ready() then
    session:hangup()
end
