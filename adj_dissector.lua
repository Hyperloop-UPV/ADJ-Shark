-- adj_dissector.lua
-- Wireshark UDP dissector for the ADJ Protocol
--
-- Reads all packet and measurement definitions at runtime from the ADJ JSON
-- files, so it stays in sync with the protocol as it evolves.
--
-- INSTALL
--   Copy this file to your Wireshark plugins directory:
--     Linux  : ~/.config/wireshark/plugins/
--     macOS  : ~/Library/Application Support/Wireshark/plugins/
--     Windows: %APPDATA%\Wireshark\plugins\
--
-- CONFIGURE
--   Edit > Preferences > Protocols > ADJ
--   Set "ADJ Directory Path" to the absolute path of the adj/ folder
--   e.g.  /home/user/HyperLoop/ADJ-Shark/adj
--
-- RELOAD
--   After changing JSON files or the preference, press Ctrl+Shift+L
--   (Analyze > Reload Lua Plugins) or reopen the capture.

-- ═══════════════════════════════════════════════════════════════
-- §1  Minimal Pure-Lua JSON Parser
-- ═══════════════════════════════════════════════════════════════

local json = {}
do
    -- skip whitespace; returns index of first non-space character
    local function ws(s, i)
        local _, j = s:find("^%s*", i)
        return j + 1
    end

    local parse_value  -- forward declaration

    local function parse_string(s, i)
        local out, j = {}, i + 1
        while j <= #s do
            local c = s:sub(j, j)
            if c == '"' then
                return table.concat(out), j + 1
            elseif c == '\\' then
                j = j + 1
                local e   = s:sub(j, j)
                local esc = { ['"']='"', ['\\']='\\', ['/']='/',
                              b='\b', f='\f', n='\n', r='\r', t='\t' }
                out[#out + 1] = esc[e] or e
            else
                out[#out + 1] = c
            end
            j = j + 1
        end
        error("Unterminated JSON string")
    end

    local function parse_array(s, i)
        local a, j = {}, ws(s, i + 1)
        if s:sub(j, j) == ']' then return a, j + 1 end
        while true do
            local v; v, j = parse_value(s, j)
            a[#a + 1] = v
            j = ws(s, j)
            local c = s:sub(j, j)
            if     c == ']' then return a, j + 1
            elseif c == ',' then j = ws(s, j + 1)
            else error("JSON array: expected ',' or ']'") end
        end
    end

    local function parse_object(s, i)
        local o, j = {}, ws(s, i + 1)
        if s:sub(j, j) == '}' then return o, j + 1 end
        while true do
            j = ws(s, j)
            local k; k, j = parse_string(s, j)
            j = ws(s, j)
            if s:sub(j, j) ~= ':' then error("JSON object: expected ':'") end
            j = ws(s, j + 1)
            local v; v, j = parse_value(s, j)
            o[k] = v
            j = ws(s, j)
            local c = s:sub(j, j)
            if     c == '}' then return o, j + 1
            elseif c == ',' then j = ws(s, j + 1)
            else error("JSON object: expected ',' or '}'") end
        end
    end

    parse_value = function(s, i)
        i = ws(s, i)
        local c = s:sub(i, i)
        if     c == '"' then return parse_string(s, i)
        elseif c == '{' then return parse_object(s, i)
        elseif c == '[' then return parse_array(s, i)
        elseif c == 't' then return true,  i + 4
        elseif c == 'f' then return false, i + 5
        elseif c == 'n' then return nil,   i + 4
        else
            local n, j = s:match("^(-?%d+%.?%d*[eE]?[+-]?%d*)()", i)
            if n then return tonumber(n), j end
            error("JSON: unexpected character '" .. c .. "' at position " .. i)
        end
    end

    -- Public decode: returns parsed value or nil on error
    function json.decode(s)
        local ok, result = pcall(parse_value, s, 1)
        return ok and result or nil
    end
end

-- ═══════════════════════════════════════════════════════════════
-- §2  File / Path Utilities
-- ═══════════════════════════════════════════════════════════════

local function read_file(path)
    local fh = io.open(path, "r")
    if not fh then return nil end
    local content = fh:read("*all")
    fh:close()
    return content
end

-- Joins two path segments, normalising slashes
local function joinpath(base, rel)
    base = base:gsub("[/\\]+$", "")
    rel  = rel:gsub("^[/\\]+",  "")
    return base .. "/" .. rel
end

-- Returns the directory portion of a file path
local function dirname(path)
    return path:match("^(.*)[/\\][^/\\]+$") or "."
end

-- ═══════════════════════════════════════════════════════════════
-- §3  ADJ Data Model
-- ═══════════════════════════════════════════════════════════════
--
-- After loading, packets_db holds:
--   packets_db[packet_id (number)] = {
--     board : string,
--     name  : string,
--     vars  : array of {
--               name      : string,   -- human-readable measurement name
--               vtype     : string,   -- "uint8" | "float32" | "enum" | …
--               enum_vals : table?,   -- indexed array of enum strings (1-based)
--               units     : string,   -- "" if none
--             }
--   }

local packets_db  = {}
local loaded_path = nil   -- last successfully loaded adj path

-- Wire size (bytes) for each supported type
local WIRE_SIZE = {
    uint8=1,  uint16=2,  uint32=4,  uint64=8,
    int8=1,   int16=2,   int32=4,   int64=8,
    float32=4, float64=8,
    bool=1,
    enum=1,   -- always uint8 on the wire
}

-- Load one board into packets_db; returns nothing (errors are silently skipped)
local function load_board(adj_path, board_name, board_rel)
    local board_json_path = joinpath(adj_path, board_rel)
    local board_raw       = read_file(board_json_path)
    if not board_raw then return end

    local cfg = json.decode(board_raw)
    if not cfg then return end

    local board_dir = dirname(board_json_path)

    -- ── Collect all measurement definitions for this board ──────────────
    local mdb = {}
    for _, mfile in ipairs(cfg.measurements or {}) do
        local raw = read_file(joinpath(board_dir, mfile))
        if raw then
            local list = json.decode(raw)
            if list then
                for _, m in ipairs(list) do
                    if m.id then mdb[m.id] = m end
                end
            end
        end
    end

    -- ── Parse packet files and register data packets ────────────────────
    for _, pfile in ipairs(cfg.packets or {}) do
        local raw = read_file(joinpath(board_dir, pfile))
        if raw then
            local list = json.decode(raw)
            if list then
                for _, p in ipairs(list) do
                    if p.id and p.type == "data" then
                        local vars = {}
                        for _, vid in ipairs(p.variables or {}) do
                            local m = mdb[vid]
                            if m then
                                vars[#vars + 1] = {
                                    name      = m.name or vid,
                                    vtype     = m.type or "uint8",
                                    enum_vals = m.enumValues,
                                    units     = m.displayUnits or m.podUnits or "",
                                }
                            else
                                -- Measurement definition not found; keep as placeholder
                                vars[#vars + 1] = {
                                    name  = vid,
                                    vtype = "unknown",
                                    units = "",
                                }
                            end
                        end
                        packets_db[p.id] = {
                            board = board_name,
                            name  = p.name or ("Packet " .. p.id),
                            vars  = vars,
                        }
                    end
                end
            end
        end
    end
end

-- Top-level loader: reads boards.json then delegates to load_board()
local function load_adj(adj_path)
    packets_db = {}

    local boards_raw = read_file(joinpath(adj_path, "boards.json"))
    if not boards_raw then
        return false, "Cannot open " .. joinpath(adj_path, "boards.json")
    end

    local boards = json.decode(boards_raw)
    if not boards then
        return false, "Failed to parse boards.json"
    end

    for board_name, board_rel in pairs(boards) do
        load_board(adj_path, board_name, board_rel)
    end

    loaded_path = adj_path
    return true
end

-- ═══════════════════════════════════════════════════════════════
-- §4  Proto Definition & Static Fields
-- ═══════════════════════════════════════════════════════════════

-- Auto-detect adj/ directory next to this script file.
-- debug.getinfo(1,"S").source returns "@/absolute/path/to/script.lua"
local _src = debug.getinfo(1, "S").source or ""
local _script_dir = _src:match("^@(.+)[/\\][^/\\]+$") or "."
local AUTO_ADJ_PATH = _script_dir .. "/adj"

local adj_proto = Proto("ADJ", "ADJ Protocol (UDP)")

adj_proto.prefs.path = Pref.string(
    "path",
    AUTO_ADJ_PATH,
    "Absolute path to the adj/ directory  (e.g. /home/user/project/adj)"
)

-- Load JSON at script startup
load_adj(AUTO_ADJ_PATH)

-- Static ProtoFields used for the 2-byte packet ID and metadata labels.
-- Per-variable values are added as plain text tree items so that the
-- dissector works without knowing all field names at registration time.
local F = {
    packet_id  = ProtoField.uint16("adj.packet_id",   "Packet ID",   base.DEC),
    board      = ProtoField.string("adj.board",       "Board"),
    pkt_name   = ProtoField.string("adj.packet_name", "Packet Name"),
}
adj_proto.fields = { F.packet_id, F.board, F.pkt_name }

-- Expert info items
local E = {
    unknown   = ProtoExpert.new("adj.unknown_id", "Unknown packet ID",
                                expert.group.UNDECODED, expert.severity.WARN),
    truncated = ProtoExpert.new("adj.truncated",  "Payload truncated",
                                expert.group.MALFORMED, expert.severity.ERROR),
}
adj_proto.experts = { E.unknown, E.truncated }

-- ═══════════════════════════════════════════════════════════════
-- §5  Decoding Helpers
-- ═══════════════════════════════════════════════════════════════

-- Reads one typed value from the TvbRange buffer at byte offset `off`.
-- Returns: value (Lua type), bytes consumed, TvbRange slice
--          OR nil, nil on truncation
--          OR nil, 1   on unknown type (skip 1 byte)
local function decode_field(buf, off, vtype)
    local sz = WIRE_SIZE[vtype]
    if not sz then return nil, 1 end          -- unknown type
    if off + sz > buf:len() then return nil, nil end  -- truncated

    local s = buf(off, sz)
    local v

    if     vtype == "uint8"   then v = s:uint()
    elseif vtype == "uint16"  then v = s:le_uint()
    elseif vtype == "uint32"  then v = s:le_uint()
    elseif vtype == "uint64"  then v = tostring(s:le_uint64())
    elseif vtype == "int8"    then v = s:int()
    elseif vtype == "int16"   then v = s:le_int()
    elseif vtype == "int32"   then v = s:le_int()
    elseif vtype == "int64"   then v = tostring(s:le_int64())
    elseif vtype == "float32" then v = s:le_float()   -- 4-byte IEEE 754 LE
    elseif vtype == "float64" then v = s:le_float()   -- 8-byte IEEE 754 LE
    elseif vtype == "bool"    then v = (s:uint() ~= 0)
    elseif vtype == "enum"    then v = s:uint()       -- uint8 on wire
    end

    return v, sz, s
end

-- Formats a decoded value for display
local function format_value(val, var)
    if val == nil then return "(nil)" end

    if var.vtype == "bool" then
        return val and "true" or "false"

    elseif var.vtype == "enum" then
        if var.enum_vals then
            -- val is 0-based index from the wire; Lua tables are 1-based
            return var.enum_vals[val + 1] or string.format("Unknown(%d)", val)
        end
        return tostring(val)

    elseif var.vtype == "float32" or var.vtype == "float64" then
        return string.format("%.6g", val)

    else
        return tostring(val)
    end
end

-- ═══════════════════════════════════════════════════════════════
-- §6  Dissector
-- ═══════════════════════════════════════════════════════════════

function adj_proto.dissector(buf, pinfo, tree)
    if buf:len() < 2 then return 0 end

    pinfo.cols.protocol:set("ADJ")

    -- ── (Re)load ADJ data if the path has changed ───────────────────────
    local path = adj_proto.prefs.path
    if not path or path == "" then path = AUTO_ADJ_PATH end

    if path ~= loaded_path then
        load_adj(path)
    end

    -- ── Parse the 2-byte little-endian Packet ID ────────────────────────
    local pkt_id = buf(0, 2):le_uint()
    local root   = tree:add(adj_proto, buf(), "ADJ Protocol")
    root:add_le(F.packet_id, buf(0, 2))

    local pkt = packets_db[pkt_id]
    if not pkt then
        pinfo.cols.info:set(string.format(
            "ADJ: Unknown packet 0x%04X (%d)", pkt_id, pkt_id))
        root:add_proto_expert_info(E.unknown,
            string.format("No definition found for packet ID %d", pkt_id))
        return buf:len()
    end

    -- ── Metadata labels ─────────────────────────────────────────────────
    root:add(F.board,    buf(0, 0), pkt.board)
    root:add(F.pkt_name, buf(0, 0), pkt.name)

    pinfo.cols.info:set(string.format(
        "[%s] %s  (id=%d)", pkt.board, pkt.name, pkt_id))

    if #pkt.vars == 0 then return buf:len() end

    -- ── Decode variables ────────────────────────────────────────────────
    local payload_len = buf:len() - 2
    local vt  = root:add(buf(2), string.format(
        "Variables (%d)  [%d bytes payload]", #pkt.vars, payload_len))
    local off = 2

    for _, var in ipairs(pkt.vars) do
        local val, sz, slice = decode_field(buf, off, var.vtype)

        if sz == nil then
            -- Buffer too short: mark remaining vars as missing and stop
            vt:add_proto_expert_info(E.truncated,
                "Buffer too short for field: " .. var.name)
            break
        end

        if val == nil then
            -- Unknown type: skip one byte and flag it
            vt:add(buf(off, 1),
                string.format("[%s]  (unknown type: %s, skipping 1 byte)",
                    var.name, var.vtype))
            off = off + 1
        else
            local fmted = format_value(val, var)
            local label
            if var.units ~= "" then
                label = string.format("%s: %s %s", var.name, fmted, var.units)
            else
                label = string.format("%s: %s", var.name, fmted)
            end
            vt:add(slice, label)
            off = off + sz
        end
    end

    return buf:len()
end

-- ═══════════════════════════════════════════════════════════════
-- §7  Init & Registration
-- ═══════════════════════════════════════════════════════════════

-- Called by Wireshark before each new capture / on plugin reload.
-- Clears loaded_path so the JSON files are re-read fresh.
function adj_proto.init()
    loaded_path = nil
end

-- Register on UDP port 50400 (from general_info.json)
DissectorTable.get("udp.port"):add(50400, adj_proto)
