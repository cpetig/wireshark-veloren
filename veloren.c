#include "config.h"
#include <epan/packet.h>
#include <epan/dissectors/packet-tcp.h>

#define VELOREN_PORT 14004

static int proto_vlr=-1;
static dissector_handle_t vlr_handle;
static int hf_vlr_pdu_type=-1;
static int hf_vlr_hs_magic=-1;
static int hf_vlr_hs_vers=-1;
static int ett_vlr=-1;

#define FRAME_HEADER_LEN 11

#define HANDSHAKE 1
#define INIT 2
#define OPEN_STREAM 4
#define DATA_HEADER 6
#define DATA 7
#define RAW 8

/* This method dissects fully reassembled messages */
static int
dissect_vlr_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
    proto_item *ti = proto_tree_add_item(tree, proto_vlr, tvb, 0, -1, ENC_NA);
    proto_tree *foo_tree = proto_item_add_subtree(ti, ett_vlr);
    uint8_t type;
    proto_tree_add_item(foo_tree, hf_vlr_pdu_type, tvb, 0, 1, ENC_BIG_ENDIAN);

    type = tvb_get_guint8(tvb, 0);
    if (type == HANDSHAKE) {
        proto_tree_add_item(foo_tree, hf_vlr_hs_magic, tvb, 1, 7, ENC_UTF_8);
        proto_tree_add_item(foo_tree, hf_vlr_hs_vers, tvb, 8, 12, ENC_LITTLE_ENDIAN);
    }
    /* TODO: implement your dissecting code */
    return tvb_captured_length(tvb);
}

/* determine PDU length of protocol vlr */
static unsigned
get_vlr_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    uint8_t type = tvb_get_guint8(tvb, offset);
    if (type == HANDSHAKE) return 1+7+3*4;
    else if (type == INIT) return 1+16+16;
    else if (type == OPEN_STREAM) return 1+8+1+1+8;
    else if (type == DATA_HEADER) return 1+8+8+8;
    else if (type == DATA) return 1+8+2 + tvb_get_letohs(tvb, offset+9);
    else return 1;
}

static int
dissect_vlr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "VLR");
    /* Clear the info column */
    col_clear(pinfo->cinfo,COL_INFO);
#if 0

    proto_item *ti = proto_tree_add_item(tree, proto_vlr, tvb, 0, -1, ENC_LITTLE_ENDIAN);
#endif
    tcp_dissect_pdus(tvb, pinfo, tree, true, FRAME_HEADER_LEN,
                     get_vlr_message_len, dissect_vlr_message, data);
    return tvb_captured_length(tvb);
}

void
proto_register_vlr(void)
{
    static const value_string typenames[] = {
        { HANDSHAKE, "Handshake" },
        { INIT, "Init" },
        { OPEN_STREAM, "Open stream" },
        { DATA_HEADER, "Data header" },
        { DATA, "Data" },
        { RAW, "Raw" },
        { 0, NULL },
    };

    static hf_register_info hf[] = {
        { &hf_vlr_pdu_type,
            { "Type", "veloren.type",
            FT_UINT8, BASE_DEC,
            VALS(typenames), 0x0,
            NULL, HFILL }
        },
    // Handshake
        { &hf_vlr_hs_magic,
            { "Magic", "veloren.handshake.magic",
            FT_STRINGZPAD, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_vlr_hs_vers,
            { "Version", "veloren.handshake.version",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
#if 0
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
#endif
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_vlr
    };

    proto_vlr = proto_register_protocol (
        "Veloren Protocol", /* name        */
        "VLR",          /* short name  */
        "vlr"           /* filter_name */
        );

    proto_register_field_array(proto_vlr, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

}

void
proto_reg_handoff_vlr(void)
{

    vlr_handle = create_dissector_handle(dissect_vlr, proto_vlr);
    dissector_add_uint_with_preference("tcp.port", VELOREN_PORT, vlr_handle);
}
