-- customer_router.lua
-- Entry point for customer trunks that dial <inbound_prefix><number> (no 3366 in front).
-- Matches the caller's source IP + the trunk's inbound prefix from the panel-generated routing table
-- (/opt/voip/companies/routing.tsv, longest prefix wins) and hands the call to the capture flow,
-- which strips the prefix, records the caller, asks the gate and bridges to that trunk's vendor.
-- Calls that match no customer trunk return here untouched so the normal honeypot dialplan continues.
local dest = session:getVariable("destination_number") or ""
local sig_ip = session:getVariable("sip_received_ip") or session:getVariable("network_addr") or session:getVariable("sip_network_ip") or ""
if dest == "" or sig_ip == "" or not sig_ip:match("^[0-9%.]+$") then return end

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

local rf = io.open("/opt/voip/companies/routing.tsv", "r")
if not rf then return end
local best_prefix, best_company, best_trunk = nil, "", ""
for line in rf:lines() do
    if line ~= "" and line:sub(1, 1) ~= "#" then
        local cidr, cid, v, p, inp, ct, vt = line:match("^([^\t]+)\t([^\t]*)\t([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)")
        inp = inp or ""
        if cidr and inp ~= "" and ip_in_cidr(sig_ip, cidr) and dest:sub(1, #inp) == inp
           and (best_prefix == nil or #inp > #best_prefix) then
            best_prefix, best_company, best_trunk = inp, cid or "", ct or ""
        end
    end
end
rf:close()
if not best_prefix then return end   -- not a customer-prefixed call: let the rest of the dialplan handle it

session:setVariable("destination_number_ori", dest)   -- the capture script reads this, then strips the trunk prefix itself
session:consoleLog("info", "[router] customer trunk call ip=" .. sig_ip .. " company=" .. best_company .. " trunk=" .. best_trunk
                   .. " prefix=" .. best_prefix .. " dest=" .. dest .. " -> record_and_bridge_3366.lua\n")
session:execute("lua", "record_and_bridge_3366.lua")
if session:ready() then session:hangup() end
