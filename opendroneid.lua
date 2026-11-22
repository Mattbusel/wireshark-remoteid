-- opendroneid.lua
-- Wireshark/tshark dissector for ASTM F3411 Open Drone ID (Remote ID).
--
-- Dissects the Open Drone ID broadcast messages (Basic ID, Location, Self ID,
-- Auth, System, Operator ID) and the Message Pack that carries several of them
-- behind one header.
--
-- Field semantics follow the opendroneid-core-c reference and the Rust
-- `remoteid` crate (https://crates.io/crates/remoteid), byte for byte.
--
-- Two entry points are registered:
--   1. Bluetooth LE / BR-EDR Service Data for ASTM UUID 0xFFFA. This covers
--      captures of link type LINKTYPE_BLUETOOTH_LE_LL (251) and HCI, which is
--      what most Remote ID sniffers and the bundled sample capture produce.
--   2. A post-dissector that finds the ASD-STAN Wi-Fi vendor element
--      (OUI FA:0B:BC, type 0x0D) anywhere in an 802.11 frame and dissects the
--      counter and message pack that follow it.
--
-- License: MIT OR Apache-2.0. Receive/decode only; there is no transmit path.

local odid = Proto("opendroneid", "ASTM F3411 Open Drone ID (Remote ID)")

-- ---------------------------------------------------------------------------
-- Constants
-- ---------------------------------------------------------------------------

local MESSAGE_SIZE   = 25          -- every single message is 25 bytes
local ASTM_UUID16    = 0xFFFA      -- ASTM Remote ID 16-bit service UUID
local ASTM_APP_CODE  = 0x0D        -- application code after the UUID / OUI type
local EPOCH_2019     = 1546300800  -- Unix seconds at 2019-01-01 00:00:00 UTC

local MSG_BASIC_ID   = 0
local MSG_LOCATION   = 1
local MSG_AUTH       = 2
local MSG_SELF_ID    = 3
local MSG_SYSTEM     = 4
local MSG_OPERATOR   = 5
local MSG_PACK       = 15

-- ---------------------------------------------------------------------------
-- Value strings
-- ---------------------------------------------------------------------------

local vs_msg_type = {
    [0]  = "Basic ID",
    [1]  = "Location / Vector",
    [2]  = "Authentication",
    [3]  = "Self ID",
    [4]  = "System",
    [5]  = "Operator ID",
    [15] = "Message Pack",
}

local vs_id_type = {
    [0] = "None",
    [1] = "Serial Number (ANSI/CTA-2063-A)",
    [2] = "CAA Registration ID",
    [3] = "UTM Assigned UUID",
    [4] = "Specific Session ID",
}

local vs_ua_type = {
    [0]  = "None / Not Declared",
    [1]  = "Aeroplane / Fixed Wing",
    [2]  = "Helicopter or Multirotor",
    [3]  = "Gyroplane",
    [4]  = "Hybrid Lift (VTOL fixed wing)",
    [5]  = "Ornithopter",
    [6]  = "Glider",
    [7]  = "Kite",
    [8]  = "Free Balloon",
    [9]  = "Captive Balloon",
    [10] = "Airship",
    [11] = "Free Fall / Parachute",
    [12] = "Rocket",
    [13] = "Tethered Powered Aircraft",
    [14] = "Ground Obstacle",
    [15] = "Other",
}

local vs_status = {
    [0] = "Undeclared",
    [1] = "Ground",
    [2] = "Airborne",
    [3] = "Emergency",
    [4] = "Remote ID System Failure",
}

local vs_height_type = {
    [0] = "Above Takeoff",
    [1] = "Above Ground Level",
}

local vs_ew = {
    [0] = "< 180 deg",
    [1] = ">= 180 deg (+180)",
}

local vs_speed_mult = {
    [0] = "x0.25 m/s",
    [1] = "x0.75 m/s (+63.75)",
}

local vs_auth_type = {
    [0] = "None",
    [1] = "UAS ID Signature",
    [2] = "Operator ID Signature",
    [3] = "Message Set Signature",
    [4] = "Network Remote ID",
    [5] = "Specific Authentication Method",
}

local vs_desc_type = {
    [0] = "Text",
    [1] = "Emergency",
    [2] = "Extended Status",
}

local vs_operator_loc_type = {
    [0] = "Takeoff",
    [1] = "Live GNSS",
    [2] = "Fixed",
}

local vs_classification = {
    [0] = "Undeclared",
    [1] = "European Union",
}

local vs_category_eu = {
    [0] = "Undeclared",
    [1] = "Open",
    [2] = "Specific",
    [3] = "Certified",
}

local vs_class_eu = {
    [0] = "Undeclared",
    [1] = "Class C0",
    [2] = "Class C1",
    [3] = "Class C2",
    [4] = "Class C3",
    [5] = "Class C4",
    [6] = "Class C5",
    [7] = "Class C6",
}

-- ---------------------------------------------------------------------------
-- Fields
-- ---------------------------------------------------------------------------

local f = {}

-- Transport wrapper (BLE service data / Wi-Fi vendor element)
f.app_code   = ProtoField.uint8("opendroneid.app_code",   "Application Code", base.HEX)
f.counter    = ProtoField.uint8("opendroneid.msg_counter", "Message Counter", base.DEC)

-- Message pack header
f.pack_singlesize = ProtoField.uint8("opendroneid.pack.single_size", "Single Message Size", base.DEC)
f.pack_count      = ProtoField.uint8("opendroneid.pack.count",       "Message Count", base.DEC)

-- Common header (first byte of every message)
f.msg_type  = ProtoField.uint8("opendroneid.msg_type", "Message Type", base.DEC, vs_msg_type, 0xF0)
f.version   = ProtoField.uint8("opendroneid.version",  "Protocol Version", base.DEC, nil, 0x0F)

-- Basic ID
f.bid_id_type = ProtoField.uint8("opendroneid.basic_id.id_type", "ID Type", base.DEC, vs_id_type, 0xF0)
f.bid_ua_type = ProtoField.uint8("opendroneid.basic_id.ua_type", "UA Type", base.DEC, vs_ua_type, 0x0F)
f.bid_uas_id  = ProtoField.string("opendroneid.basic_id.uas_id", "UAS ID")
f.bid_uas_raw = ProtoField.bytes("opendroneid.basic_id.uas_id_raw", "UAS ID (raw)")

-- Location
f.loc_status      = ProtoField.uint8("opendroneid.location.status", "Operational Status", base.DEC, vs_status, 0xF0)
f.loc_height_type = ProtoField.uint8("opendroneid.location.height_type", "Height Type", base.DEC, vs_height_type, 0x04)
f.loc_ew          = ProtoField.uint8("opendroneid.location.ew_segment", "Direction E/W Segment", base.DEC, vs_ew, 0x02)
f.loc_speed_mult  = ProtoField.uint8("opendroneid.location.speed_mult", "Speed Multiplier", base.DEC, vs_speed_mult, 0x01)
f.loc_direction   = ProtoField.double("opendroneid.location.direction", "Track Direction (deg)")
f.loc_speed_h     = ProtoField.double("opendroneid.location.speed_h", "Horizontal Speed (m/s)")
f.loc_speed_v     = ProtoField.double("opendroneid.location.speed_v", "Vertical Speed (m/s)")
f.loc_lat         = ProtoField.double("opendroneid.location.lat", "Latitude (deg)")
f.loc_lon         = ProtoField.double("opendroneid.location.lon", "Longitude (deg)")
f.loc_alt_baro    = ProtoField.double("opendroneid.location.alt_baro", "Pressure Altitude (m)")
f.loc_alt_geo     = ProtoField.double("opendroneid.location.alt_geo", "Geodetic Altitude (m)")
f.loc_height      = ProtoField.double("opendroneid.location.height", "Height (m)")
f.loc_h_acc       = ProtoField.uint8("opendroneid.location.horiz_acc", "Horizontal Accuracy (code)", base.DEC, nil, 0x0F)
f.loc_v_acc       = ProtoField.uint8("opendroneid.location.vert_acc", "Vertical Accuracy (code)", base.DEC, nil, 0xF0)
f.loc_s_acc       = ProtoField.uint8("opendroneid.location.speed_acc", "Speed Accuracy (code)", base.DEC, nil, 0x0F)
f.loc_baro_acc    = ProtoField.uint8("opendroneid.location.baro_acc", "Baro Altitude Accuracy (code)", base.DEC, nil, 0xF0)
f.loc_timestamp   = ProtoField.double("opendroneid.location.timestamp", "Timestamp (s after the hour)")
f.loc_ts_acc      = ProtoField.uint8("opendroneid.location.ts_acc", "Timestamp Accuracy (code)", base.DEC, nil, 0x0F)

-- Auth
f.auth_type       = ProtoField.uint8("opendroneid.auth.type", "Authentication Type", base.DEC, vs_auth_type, 0xF0)
f.auth_page       = ProtoField.uint8("opendroneid.auth.page", "Page Number", base.DEC, nil, 0x0F)
f.auth_last_page  = ProtoField.uint8("opendroneid.auth.last_page", "Last Page Index", base.DEC)
f.auth_length     = ProtoField.uint8("opendroneid.auth.length", "Auth Length (bytes)", base.DEC)
f.auth_timestamp  = ProtoField.uint32("opendroneid.auth.timestamp", "Timestamp (s since 2019-01-01)", base.DEC)
f.auth_data       = ProtoField.bytes("opendroneid.auth.data", "Authentication Data")

-- Self ID
f.self_desc_type  = ProtoField.uint8("opendroneid.self_id.desc_type", "Description Type", base.DEC, vs_desc_type)
f.self_desc       = ProtoField.string("opendroneid.self_id.description", "Description")

-- System
f.sys_op_loc_type   = ProtoField.uint8("opendroneid.system.op_loc_type", "Operator Location Type", base.DEC, vs_operator_loc_type, 0x03)
f.sys_classif       = ProtoField.uint8("opendroneid.system.classification", "Classification Type", base.DEC, vs_classification, 0x1C)
f.sys_op_lat        = ProtoField.double("opendroneid.system.op_lat", "Operator Latitude (deg)")
f.sys_op_lon        = ProtoField.double("opendroneid.system.op_lon", "Operator Longitude (deg)")
f.sys_area_count    = ProtoField.uint16("opendroneid.system.area_count", "Area Count", base.DEC)
f.sys_area_radius   = ProtoField.uint16("opendroneid.system.area_radius", "Area Radius (m)", base.DEC)
f.sys_area_ceiling  = ProtoField.double("opendroneid.system.area_ceiling", "Area Ceiling (m)")
f.sys_area_floor    = ProtoField.double("opendroneid.system.area_floor", "Area Floor (m)")
f.sys_category_eu   = ProtoField.uint8("opendroneid.system.category_eu", "EU Category", base.DEC, vs_category_eu, 0xF0)
f.sys_class_eu      = ProtoField.uint8("opendroneid.system.class_eu", "EU Class", base.DEC, vs_class_eu, 0x0F)
f.sys_op_alt_geo    = ProtoField.double("opendroneid.system.op_alt_geo", "Operator Geodetic Altitude (m)")
f.sys_timestamp     = ProtoField.uint32("opendroneid.system.timestamp", "Timestamp (s since 2019-01-01)", base.DEC)

-- Operator ID
f.op_id_type = ProtoField.uint8("opendroneid.operator_id.type", "Operator ID Type", base.DEC)
f.op_id      = ProtoField.string("opendroneid.operator_id.id", "Operator ID")

-- Generic / fallback
f.reserved   = ProtoField.bytes("opendroneid.reserved", "Reserved")
f.unix_time  = ProtoField.absolute_time("opendroneid.unix_time", "UTC Time")

odid.fields = f

-- Expert info
local ef_badsize = ProtoExpert.new("opendroneid.bad_size", "Truncated Open Drone ID data", expert.group.MALFORMED, expert.severity.WARN)
local ef_unknown = ProtoExpert.new("opendroneid.unknown_type", "Unknown message type", expert.group.UNDECODED, expert.severity.NOTE)
odid.experts = { ef_badsize, ef_unknown }

-- ---------------------------------------------------------------------------
-- Decoding helpers (mirror opendroneid-core-c / remoteid semantics)
-- ---------------------------------------------------------------------------

-- Altitude: 0.5 m steps from -1000 m. Raw 0 means unknown.
local function decode_altitude(raw)
    if raw == 0 then return nil end
    return raw * 0.5 - 1000.0
end

-- NUL-padded, printable-ASCII field as text. Returns the text, or nil.
local function padded_str(range)
    local bytes = range:bytes()
    local out = {}
    for i = 0, bytes:len() - 1 do
        local b = bytes:get_index(i)
        if b == 0 then break end
        if b < 0x20 or b >= 0x7f then return nil end  -- not printable ASCII
        out[#out + 1] = string.char(b)
    end
    return table.concat(out)
end

local function append_unknown_or(subtree_item, value, suffix)
    if value == nil then
        subtree_item:append_text(" (unknown)")
    elseif suffix then
        subtree_item:append_text(suffix)
    end
end

-- ---------------------------------------------------------------------------
-- Per-message dissectors. Each takes a 25-byte tvb range.
-- ---------------------------------------------------------------------------

local function dissect_basic_id(buf, tree)
    tree:add(f.bid_id_type, buf(1, 1))
    tree:add(f.bid_ua_type, buf(1, 1))
    local text = padded_str(buf(2, 20))
    if text and #text > 0 then
        tree:add(f.bid_uas_id, buf(2, 20), text)
    else
        tree:add(f.bid_uas_raw, buf(2, 20))
    end
    return text
end

local function dissect_location(buf, tree)
    local flags = buf(1, 1):uint()
    local ew   = (math.floor(flags / 2) % 2) == 1   -- bit 0x02
    local mult = (flags % 2) == 1                    -- bit 0x01

    tree:add(f.loc_status, buf(1, 1))
    tree:add(f.loc_height_type, buf(1, 1))
    tree:add(f.loc_ew, buf(1, 1))
    tree:add(f.loc_speed_mult, buf(1, 1))

    -- Direction
    local dir_raw = buf(2, 1):uint()
    local dir = dir_raw + (ew and 180.0 or 0.0)
    local dir_val = (dir == 361.0) and nil or dir
    local it = tree:add(f.loc_direction, buf(2, 1), dir_val or 0)
    append_unknown_or(it, dir_val, " deg")

    -- Horizontal speed
    local sp_raw = buf(3, 1):uint()
    local speed = mult and (sp_raw * 0.75 + 63.75) or (sp_raw * 0.25)
    local sp_val = (speed == 255.0) and nil or speed
    it = tree:add(f.loc_speed_h, buf(3, 1), sp_val or 0)
    append_unknown_or(it, sp_val, " m/s")

    -- Vertical speed (signed byte * 0.5). 63.0 means unknown.
    local vs_raw = buf(4, 1):int()   -- int() on a 1-byte range is signed
    local vspeed = vs_raw * 0.5
    local vs_val = (vspeed == 63.0) and nil or vspeed
    it = tree:add(f.loc_speed_v, buf(4, 1), vs_val or 0)
    append_unknown_or(it, vs_val, " m/s")

    -- Latitude / Longitude (int32 LE / 1e7)
    local lat = buf(5, 4):le_int() / 1e7
    local lon = buf(9, 4):le_int() / 1e7
    tree:add(f.loc_lat, buf(5, 4), lat)
    tree:add(f.loc_lon, buf(9, 4), lon)

    -- Altitudes
    local ab = decode_altitude(buf(13, 2):le_uint())
    it = tree:add(f.loc_alt_baro, buf(13, 2), ab or 0); append_unknown_or(it, ab, " m")
    local ag = decode_altitude(buf(15, 2):le_uint())
    it = tree:add(f.loc_alt_geo, buf(15, 2), ag or 0); append_unknown_or(it, ag, " m")
    local hg = decode_altitude(buf(17, 2):le_uint())
    it = tree:add(f.loc_height, buf(17, 2), hg or 0); append_unknown_or(it, hg, " m")

    -- Accuracies
    tree:add(f.loc_h_acc, buf(19, 1))
    tree:add(f.loc_v_acc, buf(19, 1))
    tree:add(f.loc_s_acc, buf(20, 1))
    tree:add(f.loc_baro_acc, buf(20, 1))

    -- Timestamp (tenths of a second after the full UTC hour). 0xFFFF unknown.
    local ts_raw = buf(21, 2):le_uint()
    local ts = (ts_raw == 0xFFFF) and nil or (ts_raw / 10.0)
    it = tree:add(f.loc_timestamp, buf(21, 2), ts or 0); append_unknown_or(it, ts, " s")
    tree:add(f.loc_ts_acc, buf(23, 1))

    local parts = {}
    if lat ~= 0 or lon ~= 0 then
        parts[#parts + 1] = string.format("%.5f, %.5f", lat, lon)
    end
    return (#parts > 0) and table.concat(parts, " ") or nil
end

local function dissect_auth(buf, tree)
    tree:add(f.auth_type, buf(1, 1))
    tree:add(f.auth_page, buf(1, 1))
    local page = buf(1, 1):bitfield(4, 4)
    if page == 0 then
        tree:add(f.auth_last_page, buf(2, 1))
        tree:add(f.auth_length, buf(3, 1))
        local ts = buf(4, 4):le_uint()
        tree:add_le(f.auth_timestamp, buf(4, 4))
        tree:add(f.unix_time, buf(4, 4), NSTime.new(ts + EPOCH_2019, 0))
        tree:add(f.auth_data, buf(8, 17))
    else
        tree:add(f.auth_data, buf(2, 23))
    end
    return nil
end

local function dissect_self_id(buf, tree)
    tree:add(f.self_desc_type, buf(1, 1))
    local text = padded_str(buf(2, 23)) or ""
    tree:add(f.self_desc, buf(2, 23), text)
    return (#text > 0) and text or nil
end

local function dissect_system(buf, tree)
    tree:add(f.sys_op_loc_type, buf(1, 1))
    tree:add(f.sys_classif, buf(1, 1))
    local lat = buf(2, 4):le_int() / 1e7
    local lon = buf(6, 4):le_int() / 1e7
    tree:add(f.sys_op_lat, buf(2, 4), lat)
    tree:add(f.sys_op_lon, buf(6, 4), lon)
    tree:add_le(f.sys_area_count, buf(10, 2))
    tree:add(f.sys_area_radius, buf(12, 1), buf(12, 1):uint() * 10)
    local ceil = decode_altitude(buf(13, 2):le_uint())
    local it = tree:add(f.sys_area_ceiling, buf(13, 2), ceil or 0); append_unknown_or(it, ceil, " m")
    local floor = decode_altitude(buf(15, 2):le_uint())
    it = tree:add(f.sys_area_floor, buf(15, 2), floor or 0); append_unknown_or(it, floor, " m")
    tree:add(f.sys_category_eu, buf(17, 1))
    tree:add(f.sys_class_eu, buf(17, 1))
    local alt = decode_altitude(buf(18, 2):le_uint())
    it = tree:add(f.sys_op_alt_geo, buf(18, 2), alt or 0); append_unknown_or(it, alt, " m")
    local ts = buf(20, 4):le_uint()
    tree:add_le(f.sys_timestamp, buf(20, 4))
    if ts ~= 0 then
        tree:add(f.unix_time, buf(20, 4), NSTime.new(ts + EPOCH_2019, 0))
    end
    if lat ~= 0 or lon ~= 0 then
        return string.format("operator %.5f, %.5f", lat, lon)
    end
    return nil
end

local function dissect_operator_id(buf, tree)
    tree:add(f.op_id_type, buf(1, 1))
    local text = padded_str(buf(2, 20)) or ""
    tree:add(f.op_id, buf(2, 20), text)
    return (#text > 0) and text or nil
end

local dispatch = {
    [MSG_BASIC_ID] = dissect_basic_id,
    [MSG_LOCATION] = dissect_location,
    [MSG_AUTH]     = dissect_auth,
    [MSG_SELF_ID]  = dissect_self_id,
    [MSG_SYSTEM]   = dissect_system,
    [MSG_OPERATOR] = dissect_operator_id,
}

-- Dissect one 25-byte message. Returns a short summary string for the Info col.
local function dissect_message(buf, pinfo, parent)
    if buf:len() < MESSAGE_SIZE then
        parent:add_proto_expert_info(ef_badsize)
        return nil
    end
    local msg = buf(0, MESSAGE_SIZE)
    local mtype = msg(0, 1):bitfield(0, 4)
    local name = vs_msg_type[mtype] or string.format("Unknown (0x%X)", mtype)

    local tree = parent:add(odid, msg, "Open Drone ID Message: " .. name)
    tree:add(f.msg_type, msg(0, 1))
    tree:add(f.version, msg(0, 1))

    local handler = dispatch[mtype]
    local summary
    if handler then
        summary = handler(msg, tree)
    else
        tree:add_proto_expert_info(ef_unknown)
    end

    if summary then
        tree:append_text(" (" .. summary .. ")")
        return name .. " " .. summary
    end
    return name
end

-- Dissect a Message Pack: 3-byte header then N messages.
local function dissect_pack(buf, pinfo, parent)
    if buf:len() < 3 then
        parent:add_proto_expert_info(ef_badsize)
        return nil
    end
    local count = buf(2, 1):uint()
    local tree = parent:add(odid, buf, string.format("Open Drone ID Message Pack (%d messages)", count))
    tree:add(f.msg_type, buf(0, 1))
    tree:add(f.version, buf(0, 1))
    tree:add(f.pack_singlesize, buf(1, 1))
    tree:add(f.pack_count, buf(2, 1))

    local summaries = {}
    local off = 3
    for i = 1, count do
        if buf:len() < off + MESSAGE_SIZE then
            tree:add_proto_expert_info(ef_badsize)
            break
        end
        local s = dissect_message(buf(off, MESSAGE_SIZE), pinfo, tree)
        if s then summaries[#summaries + 1] = s end
        off = off + MESSAGE_SIZE
    end
    return string.format("Pack: %s", table.concat(summaries, "; "))
end

-- Dissect an Open Drone ID frame that begins at its header byte: a single
-- message, or a message pack (high nibble 0xF).
local function dissect_frame(buf, pinfo, parent)
    if buf:len() < 1 then return nil end
    local hi = buf(0, 1):bitfield(0, 4)
    if hi == MSG_PACK then
        return dissect_pack(buf, pinfo, parent)
    else
        return dissect_message(buf, pinfo, parent)
    end
end

-- ---------------------------------------------------------------------------
-- Transport entry points
-- ---------------------------------------------------------------------------

-- Dissect the ASTM Service Data / vendor payload: application code 0x0D, a
-- one-byte counter, then the Open Drone ID frame.
local function dissect_transport(buf, pinfo, tree, transport_name)
    if buf:len() < 3 then return 0 end
    pinfo.cols.protocol = "ODID"

    local wrap = tree:add(odid, buf(), "ASTM Remote ID (" .. transport_name .. ")")
    wrap:add(f.app_code, buf(0, 1))
    wrap:add(f.counter, buf(1, 1))

    local summary = dissect_frame(buf(2), pinfo, wrap)
    if summary then
        pinfo.cols.info:set("Remote ID: " .. summary)
    else
        pinfo.cols.info:set("Remote ID")
    end
    return buf:len()
end

-- Main dissector (used when invoked directly, e.g. via "Decode As" on a
-- payload that already starts at the application code).
function odid.dissector(buf, pinfo, tree)
    return dissect_transport(buf, pinfo, tree, "payload")
end

-- 1) Bluetooth: registered on the ASTM 16-bit service UUID. Wireshark's
--    Bluetooth dissector hands us the service data starting at the byte after
--    the UUID (the application code).
do
    local bt_table = DissectorTable.get("bluetooth.uuid")
    if bt_table then
        -- 16-bit UUIDs are keyed as the full 128-bit base-UUID string.
        bt_table:add("0000fffa-0000-1000-8000-00805f9b34fb", odid)
        -- Some builds key 16-bit UUIDs by their short hex form; register both.
        pcall(function() bt_table:add("fffa", odid) end)
    end
end

-- 2) Wi-Fi: a post-dissector that scans each frame for the ASD-STAN vendor
--    element (OUI FA:0B:BC, OUI type 0x0D) and dissects the counter + pack
--    that follow it. This handles 802.11 Beacon / probe-response captures
--    without depending on the internal vendor-element dissector table.
local wifi_odid = Proto("opendroneid_wifi", "Open Drone ID over Wi-Fi (ASD-STAN)")
wifi_odid.fields = {}

function wifi_odid.dissector(buf, pinfo, tree)
    local len = buf:len()
    if len < 6 then return end
    -- Search for the vendor-element signature FA 0B BC 0D.
    local hay = buf():bytes()
    for i = 0, len - 6 do
        if hay:get_index(i)   == 0xFA and
           hay:get_index(i+1) == 0x0B and
           hay:get_index(i+2) == 0xBC and
           hay:get_index(i+3) == 0x0D then
            -- Confirm it sits right after an 802.11 vendor tag (ID 221) so we
            -- do not fire on a coincidental byte run.
            local is_tag = (i >= 2) and (hay:get_index(i-2) == 221)
            if is_tag then
                pinfo.cols.protocol = "ODID"
                local counter_off = i + 4
                local wrap = tree:add(wifi_odid, buf(i, len - i),
                    "ASTM Remote ID (Wi-Fi Beacon vendor element)")
                wrap:add(f.counter, buf(counter_off, 1))
                local summary = dissect_frame(buf(counter_off + 1), pinfo, wrap)
                if summary then
                    pinfo.cols.info:set("Remote ID: " .. summary)
                end
                return
            end
        end
    end
end

register_postdissector(wifi_odid)
