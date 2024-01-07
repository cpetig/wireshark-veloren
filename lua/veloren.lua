-------------------------------------------------------------------------------
-- Veloren packet dissector
-- Copyright (c) 2023, Christof Petig
-- This code is covered by the BSD (3 clause) license
--
-- Based on the FPM dissector by Hadriel Kaplan <hadriel@128technology.com>
-- Copyright (c) 2015, Hadriel Kaplan
-- This code is in the Public Domain, or the BSD (3 clause) license
-- if Public Domain does not apply in your country.
--
-- original URL https://wiki.wireshark.org/uploads/__moin_import__/attachments/Lua/Examples/fpm.lua
--
-------------------------------------------------------------------------------

----------------------------------------
-- do not modify this table
local debug_level = {
    DISABLED = 0,
    LEVEL_1  = 1,
    LEVEL_2  = 2
}

local DEBUG = debug_level.LEVEL_1

local default_settings =
{
    debug_level  = DEBUG,
    enabled      = true, -- whether this dissector is enabled or not
    port         = 14004, -- default TCP port number for Veloren
    max_msg_len  = 4096, -- max length of FPM message
    subdissect   = true, -- whether to call sub-dissector or not
}


local dprint = function() end
local dprint2 = function() end
local function resetDebugLevel()
    if default_settings.debug_level > debug_level.DISABLED then
        dprint = function(...)
            print(table.concat({"Lua: ", ...}," "))
        end

        if default_settings.debug_level > debug_level.LEVEL_1 then
            dprint2 = dprint
        end
    else
        dprint = function() end
        dprint2 = dprint
    end
end
-- call it now
resetDebugLevel()


--------------------------------------------------------------------------------
-- creates a Proto object, but doesn't register it yet
local fpm_proto = Proto("veloren", "Veloren Header")


----------------------------------------
-- a function to convert tables of enumerated types to value-string tables
-- i.e., from { "name" = number } to { number = "name" }
local function makeValString(enumTable)
    local t = {}
    for name,num in pairs(enumTable) do
        t[num] = name
    end
    return t
end

local msgtype = {
    HANDSHAKE = 1,
    INIT = 2,
    OPEN_STREAM = 4,
    DATA_HEADER = 6,
    DATA = 7,
    RAW = 8,
}
local msgtype_valstr = makeValString(msgtype)


----------------------------------------
-- a table of all of our Protocol's fields
local hdr_fields =
{
    type   = ProtoField.uint8 ("veloren.type", "Type", base.DEC, msgtype_valstr),

    -- Handshake
    magic = ProtoField.new ("veloren.handshake.magic", "Magic", ftypes.STRING),
    version = ProtoField.new ("veloren.handshake.version", "Version", ftypes.NONE),

    -- Init
    pid = ProtoField.bytes("veloren.init.pid", "Pid", base.SPACE),
    secret = ProtoField.bytes ("veloren.init.secret", "Secret", base.SPACE),

    -- Open
    stream_id = ProtoField.uint64 ("veloren.open.sid", "SId", base.DEC),
    prio = ProtoField.uint8 ("veloren.open.prio", "Prio", base.DEC),
    promises = ProtoField.uint8 ("veloren.open.promises", "Promises", base.HEX),
    bandwidth = ProtoField.uint64 ("veloren.open.bandwidth", "Guaranteed Bandwidth", base.DEC),

    -- Header
    mid = ProtoField.uint64 ("veloren.hdr.mid", "MId", base.DEC),
    sid = ProtoField.uint64 ("veloren.hdr.sid", "SId", base.DEC),
    len = ProtoField.uint64 ("veloren.hdr.length", "Length", base.DEC),

    -- Data
    mid2 = ProtoField.uint64 ("veloren.data.mid", "MId", base.DEC),
    len2 = ProtoField.uint16 ("veloren.data.len", "Length", base.DEC),
    data = ProtoField.bytes ("veloren.data.data", "Data", base.SPACE),
}

-- register the ProtoFields
fpm_proto.fields = hdr_fields

dprint2("Veloren ProtoFields registered")


-- due to a bug in older (prior to 1.12) wireshark versions, we need to keep newly created
-- Tvb's for longer than the duration of the dissect function (see bug 10888)
-- this bug only affects dissectors that create new Tvb's, which is not that common
-- but this FPM dissector happens to do it in order to create the fake SLL header
-- to pass on to the Netlink dissector
local tvbs = {}

---------------------------------------
-- This function will be invoked by Wireshark during initialization, such as
-- at program start and loading a new file
function fpm_proto.init()
    -- reset the save Tvbs
    tvbs = {}
end


-- this is the size of the FPM message header (4 bytes) and the minimum FPM
-- message size we need to figure out how much the rest of the Netlink message
-- will be
local FPM_MSG_HDR_LEN = 1

-- some forward "declarations" of helper functions we use in the dissector
local dissectVeloren, CalcLength

--------------------------------------------------------------------------------
-- The following creates the callback function for the dissector.
-- It's the same as doing "fpm_proto.dissector = function (tvbuf,pkt,root)"
-- The 'tvbuf' is a Tvb object, 'pktinfo' is a Pinfo object, and 'root' is a TreeItem object.
-- Whenever Wireshark dissects a packet that our Proto is hooked into, it will call
-- this function and pass it these arguments for the packet it's dissecting.
function fpm_proto.dissector(tvbuf, pktinfo, root)
    dprint2("fpm_proto.dissector called")
    -- reset the save Tvbs
    tvbs = {}

    -- get the length of the packet buffer (Tvb).
    local pktlen = tvbuf:len()

    local bytes_consumed = 0

    -- we do this in a while loop, because there could be multiple FPM messages
    -- inside a single TCP segment, and thus in the same tvbuf - but our
    -- fpm_proto.dissector() will only be called once per TCP segment, so we
    -- need to do this loop to dissect each FPM message in it
    while bytes_consumed < pktlen do

        -- We're going to call our "dissect()" function, which is defined
        -- later in this script file. The dissect() function returns the
        -- length of the FPM message it dissected as a positive number, or if
        -- it's a negative number then it's the number of additional bytes it
        -- needs if the Tvb doesn't have them all. If it returns a 0, it's a
        -- dissection error.
        local result = dissectVeloren(tvbuf, pktinfo, root, bytes_consumed)

        if result > 0 then
            -- we successfully processed an FPM message, of 'result' length
            bytes_consumed = bytes_consumed + result
            -- go again on another while loop
        elseif result == 0 then
            -- If the result is 0, then it means we hit an error of some kind,
            -- so return 0. Returning 0 tells Wireshark this packet is not for
            -- us, and it will try heuristic dissectors or the plain "data"
            -- one, which is what should happen in this case.
            return 0
        else
            -- we need more bytes, so set the desegment_offset to what we
            -- already consumed, and the desegment_len to how many more
            -- are needed
            pktinfo.desegment_offset = bytes_consumed

            -- invert the negative result so it's a positive number
            result = -result

            pktinfo.desegment_len = result

            -- even though we need more bytes, this packet is for us, so we
            -- tell wireshark all of its bytes are for us by returning the
            -- number of Tvb bytes we "successfully processed", namely the
            -- length of the Tvb
            return pktlen
        end        
    end

    -- In a TCP dissector, you can either return nothing, or return the number of
    -- bytes of the tvbuf that belong to this protocol, which is what we do here.
    -- Do NOT return the number 0, or else Wireshark will interpret that to mean
    -- this packet did not belong to your protocol, and will try to dissect it
    -- with other protocol dissectors (such as heuristic ones)
    return bytes_consumed
end

CalcLength = function (buf, offset)
    local type = buf:range(offset, 1):uint()
    if (type == msgtype.HANDSHAKE) then
        local handshakelen = 1+7+3*4
        if buf:len() < handshakelen then 
            return -DESEGMENT_ONE_MORE_SEGMENT
        else
            return handshakelen
        end
    elseif (type == msgtype.INIT) then
        local len = 1+16+16
        if buf:len() < len then 
            return -DESEGMENT_ONE_MORE_SEGMENT
        else
            return len
        end
    elseif (type == msgtype.OPEN_STREAM) then
        local len = 1+8+1+1+8
        if buf:len() < len then 
            return -DESEGMENT_ONE_MORE_SEGMENT
        else
            return len
        end
    elseif (type == msgtype.DATA_HEADER) then
        local len = 1+8+8+8
        if buf:len() < len then 
            return -DESEGMENT_ONE_MORE_SEGMENT
        else
            return len
        end
    elseif (type == msgtype.DATA) then
        local len = 1+8+2
        if buf:len() < len then 
            return -DESEGMENT_ONE_MORE_SEGMENT
        end
        local len = len + buf:range(offset+9,2):le_uint()
        if buf:len() < len then 
            return -DESEGMENT_ONE_MORE_SEGMENT
        else
            return len
        end
    else   
        return buf:len()
    end
end

----------------------------------------
-- This function returns the length of the FPM message it dissected as a
-- positive number, or as a negative number the number of additional bytes it
-- needs if the Tvb doesn't have them all, or a 0 for error.
--
dissectVeloren = function (tvbuf, pktinfo, root, offset)

    local length = CalcLength(tvbuf, offset)

    if length <= 0 then
        return length
    end

    -- if we got here, then we have a whole message in the Tvb buffer
    -- so let's finish dissecting it...

    -- set the protocol column to show our protocol name
    pktinfo.cols.protocol:set("VLRN")

    -- set the INFO column too, but only if we haven't already set it before
    -- for this frame/packet, because this function can be called multiple
    -- times per packet/Tvb
    if string.find(tostring(pktinfo.cols.info), "VLRN") == nil then
        local start = tostring(pktinfo.cols.info):sub(1, 16)
        pktinfo.cols.info:set(start.."VLRN")
    end

    -- We start by adding our protocol to the dissection display tree.
    local tree = root:add(fpm_proto, tvbuf:range(offset, length))

    local veloren_type = tvbuf:range(offset, 1)
    local type_val  = veloren_type:uint()
    tree:add(hdr_fields.type, veloren_type)

    if type_val == msgtype.HANDSHAKE then
        if string.find(tostring(pktinfo.cols.info), "VLRN:") == nil then
            pktinfo.cols.info:append(": Handshake")
        else
            pktinfo.cols.info:append(", Handshake")
        end

        tree:add(hdr_fields.magic, tvbuf:range(offset+1, 7))
        local version = ": "..tostring(tvbuf:range(offset+8, 4):le_uint()).."."..tostring(tvbuf:range(offset+12, 4):le_uint()).."."..tostring(tvbuf:range(offset+16, 4):le_uint())
        tree:add_le(hdr_fields.version, tvbuf:range(offset+8, 12)):append_text(version)
        pktinfo.cols.info:append(version)
    elseif type_val == msgtype.INIT then
        if string.find(tostring(pktinfo.cols.info), "VLRN:") == nil then
            pktinfo.cols.info:append(": Init")
        else
            pktinfo.cols.info:append(", Init")
        end
        tree:add_le(hdr_fields.pid, tvbuf:range(offset+1, 16))
        tree:add_le(hdr_fields.secret, tvbuf:range(offset+17, 16))
    elseif type_val == msgtype.OPEN_STREAM then
        if string.find(tostring(pktinfo.cols.info), "VLRN:") == nil then
            pktinfo.cols.info:append(": Open")
        else
            pktinfo.cols.info:append(", Open")
        end
        tree:add_le(hdr_fields.stream_id, tvbuf:range(offset+1, 8))
        tree:add(hdr_fields.prio, tvbuf:range(offset+9, 1))
        tree:add(hdr_fields.promises, tvbuf:range(offset+10, 1))
        tree:add_le(hdr_fields.bandwidth, tvbuf:range(offset+11, 8))
        pktinfo.cols.info:append(" S"..tostring(tvbuf:range(offset+1,4):le_uint()))
        pktinfo.cols.info:append(" P"..tostring(tvbuf:range(offset+9,1):uint()))
    elseif type_val == msgtype.DATA_HEADER then
        if string.find(tostring(pktinfo.cols.info), "VLRN:") == nil then
            pktinfo.cols.info:append(": Hdr")
        else
            pktinfo.cols.info:append(", Hdr")
        end
        tree:add_le(hdr_fields.mid, tvbuf:range(offset+1, 8))
        tree:add_le(hdr_fields.sid, tvbuf:range(offset+9, 8))
        tree:add_le(hdr_fields.len, tvbuf:range(offset+17, 8))
        local mid = tvbuf:range(offset+1, 4):le_uint()
        local sid = tvbuf:range(offset+9, 4):le_uint()
        local len = tvbuf:range(offset+17, 4):le_uint()
        -- datalength[sid] = len
        pktinfo.cols.info:append(" #"..tostring(mid))
        pktinfo.cols.info:append(" S"..tostring(sid))
        pktinfo.cols.info:append(" L"..tostring(len))
    elseif type_val == msgtype.DATA then
        if string.find(tostring(pktinfo.cols.info), "VLRN:") == nil then
            pktinfo.cols.info:append(": Data")
        else
            pktinfo.cols.info:append(", Data")
        end
        tree:add_le(hdr_fields.mid2, tvbuf:range(offset+1, 8))
        local len = tvbuf:range(offset+9, 2):le_uint()
        tree:add_le(hdr_fields.len2, tvbuf:range(offset+9, 2))
        tree:add(hdr_fields.data, tvbuf:range(offset+11, len))
        local mid = tvbuf:range(offset+1, 4):le_uint()
        pktinfo.cols.info:append(" #"..tostring(mid))
        pktinfo.cols.info:append(" L"..tostring(len))
    else
        if string.find(tostring(pktinfo.cols.info), "VLRN:") == nil then
            pktinfo.cols.info:append(": Unknown")
        else
            pktinfo.cols.info:append(", Unknown")
        end
    end

    return length
end

--------------------------------------------------------------------------------
-- We want to have our protocol dissection invoked for a specific TCP port,
-- so get the TCP dissector table and add our protocol to it.
local function enableDissector()
    -- using DissectorTable:set() removes existing dissector(s), whereas the
    -- DissectorTable:add() one adds ours before any existing ones, but
    -- leaves the other ones alone, which is better
    DissectorTable.get("tcp.port"):add(default_settings.port, fpm_proto)
end
-- call it now, because we're enabled by default
enableDissector()

local function disableDissector()
    DissectorTable.get("tcp.port"):remove(default_settings.port, fpm_proto)
end


--------------------------------------------------------------------------------
-- preferences handling stuff
--------------------------------------------------------------------------------

local debug_pref_enum = {
    { 1,  "Disabled", debug_level.DISABLED },
    { 2,  "Level 1",  debug_level.LEVEL_1  },
    { 3,  "Level 2",  debug_level.LEVEL_2  },
}

----------------------------------------
-- register our preferences
fpm_proto.prefs.enabled     = Pref.bool("Dissector enabled", default_settings.enabled,
                                        "Whether the Veloren dissector is enabled or not")

fpm_proto.prefs.subdissect  = Pref.bool("Enable sub-dissectors", default_settings.subdissect,
                                        "Whether the Veloren packet's content" ..
                                        " should be dissected or not")

fpm_proto.prefs.debug       = Pref.enum("Debug", default_settings.debug_level,
                                        "The debug printing level", debug_pref_enum)

----------------------------------------
-- the function for handling preferences being changed
function fpm_proto.prefs_changed()
    dprint2("prefs_changed called")

    default_settings.subdissect  = fpm_proto.prefs.subdissect

    default_settings.debug_level = fpm_proto.prefs.debug
    resetDebugLevel()

    if default_settings.enabled ~= fpm_proto.prefs.enabled then
        default_settings.enabled = fpm_proto.prefs.enabled
        if default_settings.enabled then
            enableDissector()
        else
            disableDissector()
        end
        -- have to reload the capture file for this type of change
        reload()
    end

end

dprint2("pcapfile Prefs registered")
