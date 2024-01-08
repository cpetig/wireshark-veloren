#include "config.h"
#include <epan/packet.h>
#include <epan/dissectors/packet-tcp.h>
#include <veloren_dissector.h>

#define VELOREN_PORT 14004

static int proto_vlr=-1;
static dissector_handle_t vlr_handle;
static int hf_vlr_pdu_type=-1;
static int hf_vlr_hs_magic=-1;
static int hf_vlr_hs_vers=-1;
static int hf_vlr_in_pid=-1;
static int hf_vlr_in_secret=-1;
static int hf_vlr_op_pri=-1;
static int hf_vlr_op_prom=-1;
static int hf_vlr_op_sid=-1;
static int hf_vlr_op_bandw=-1;
static int hf_vlr_hd_mid=-1;
static int hf_vlr_hd_sid=-1;
static int hf_vlr_hd_len=-1;
static int hf_vlr_dt_mid=-1;
static int hf_vlr_dt_data=-1;
static int hf_vlr_dt_len=-1;
static int hf_vlr_dt_meaning=-1;
static int ett_vlr=-1;

#define FRAME_HEADER_LEN 11

#define HANDSHAKE 1
#define INIT 2
#define OPEN_STREAM 4
#define DATA_HEADER 6
#define DATA 7
#define RAW 8

struct active_stream {
    uint64_t mid; // key
    uint64_t sid;
    uint64_t length;
    uint64_t stored;
    uint8_t *storage;
};

#define NUMBER_ACTIVE_STREAMS 8
static struct active_stream active_streams[NUMBER_ACTIVE_STREAMS] = {{0},{0},{0},{0}, {0},{0},{0},{0}};

/* This method dissects fully reassembled messages */
static int
dissect_vlr_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
    proto_item *ti = proto_tree_add_item(tree, proto_vlr, tvb, 0, -1, ENC_NA);
    proto_tree *foo_tree = proto_item_add_subtree(ti, ett_vlr);
    uint8_t type;
    proto_tree_add_item(foo_tree, hf_vlr_pdu_type, tvb, 0, 1, ENC_LITTLE_ENDIAN);

    type = tvb_get_guint8(tvb, 0);
    if (type == HANDSHAKE) {
        proto_item* item=NULL;
        col_append_str(pinfo->cinfo, COL_INFO, "HandShake ");
        proto_tree_add_item(foo_tree, hf_vlr_hs_magic, tvb, 1, 7, ENC_UTF_8);
        item = proto_tree_add_item(foo_tree, hf_vlr_hs_vers, tvb, 8, 12, ENC_LITTLE_ENDIAN);
        proto_item_append_text(item, ": %u.%u.%u", tvb_get_letohl(tvb, 8),tvb_get_letohl(tvb, 12),tvb_get_letohl(tvb, 16));
    }
    else if (type == INIT) {
        col_append_str(pinfo->cinfo, COL_INFO, "Init ");
        proto_tree_add_item(foo_tree, hf_vlr_in_pid, tvb, 1, 16, ENC_SEP_SPACE);
        proto_tree_add_item(foo_tree, hf_vlr_in_secret, tvb, 17, 16, ENC_SEP_SPACE);
    }
    else if (type == OPEN_STREAM) {
        proto_tree_add_item(foo_tree, hf_vlr_op_sid, tvb, 1, 8, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(foo_tree, hf_vlr_op_pri, tvb, 9, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(foo_tree, hf_vlr_op_prom, tvb, 10, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(foo_tree, hf_vlr_op_bandw, tvb, 11, 8, ENC_LITTLE_ENDIAN);
        col_append_fstr(pinfo->cinfo, COL_INFO, "Open S%d P%d ", (int)(tvb_get_letoh64(tvb, 1)), tvb_get_guint8(tvb, 9));
    }
    else if (type == DATA_HEADER) {
        uint32_t i=0;
        proto_tree_add_item(foo_tree, hf_vlr_hd_mid, tvb, 1, 8, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(foo_tree, hf_vlr_hd_sid, tvb, 9, 8, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(foo_tree, hf_vlr_hd_len, tvb, 17, 8, ENC_LITTLE_ENDIAN);
        col_append_fstr(pinfo->cinfo, COL_INFO, "DHdr S%d L%d ", (int)(tvb_get_letoh64(tvb, 9)), 
            (int)(tvb_get_letoh64(tvb, 17)));
        for (i=0;i<NUMBER_ACTIVE_STREAMS;++i) {
            if (active_streams[i].storage==NULL) {
                active_streams[i].mid = tvb_get_letoh64(tvb, 1);
                active_streams[i].sid = tvb_get_letoh64(tvb, 9);
                active_streams[i].length = tvb_get_letoh64(tvb, 17);
                active_streams[i].stored = 0;
                if (active_streams[i].length<20*1024*1024)
                    active_streams[i].storage = malloc(active_streams[i].length);
                break;
            }
        }
    }
    else if (type == DATA) {
        int len = tvb_get_letohis(tvb, 9);
        uint32_t i=0;
        proto_tree_add_item(foo_tree, hf_vlr_dt_mid, tvb, 1, 8, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(foo_tree, hf_vlr_dt_len, tvb, 9, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(foo_tree, hf_vlr_dt_data, tvb, 11, len, ENC_LITTLE_ENDIAN);
        for (i=0;i<NUMBER_ACTIVE_STREAMS;++i) {
            if (active_streams[i].mid == tvb_get_letoh64(tvb, 1) && active_streams[i].storage!=NULL) {
                // limit
                if (active_streams[i].stored + len > active_streams[i].length) {
                    len = active_streams[i].length-active_streams[i].stored;
                }
                tvb_memcpy(tvb, active_streams[i].storage+active_streams[i].stored, 11, len);
                active_streams[i].stored += len;
                if (active_streams[i].stored==active_streams[i].length) {
                    proto_item* item=NULL;
                    result_handle parsed = NULL;
                    int from_server = pinfo->srcport == VELOREN_PORT;
                    // handle the data
                    parsed = ingest_data(active_streams[i].sid, from_server, active_streams[i].storage, active_streams[i].stored);
                    item = proto_tree_add_item(foo_tree, hf_vlr_dt_meaning, tvb, 11, len, ENC_NA);
                    proto_item_append_text(item, ": %s", get_long_text(parsed));
                    col_append_str(pinfo->cinfo, COL_INFO, get_short_representation(parsed));
                    free_handle(parsed);
                    // free
                    free(active_streams[i].storage);
                    active_streams[i].storage = NULL;
                    active_streams[i].stored = 0;
                    active_streams[i].mid = 0;
                    active_streams[i].sid = 0;
                    active_streams[i].length = 0;
                }
                break;
            }
        }
    }
    else {
        col_append_str(pinfo->cinfo, COL_INFO, "Unknown ");
    }
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
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Veloren");
    /* Clear the info column */
    col_clear(pinfo->cinfo,COL_INFO);
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
    // Init
        { &hf_vlr_in_pid,
            { "Pid", "veloren.init.pid",
            FT_BYTES, ENC_SEP_SPACE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_vlr_in_secret,
            { "Secret", "veloren.init.secret",
            FT_BYTES, ENC_SEP_SPACE,
            NULL, 0x0,
            NULL, HFILL }
        },
    // Open
        { &hf_vlr_op_sid,
            { "StreamId", "veloren.open.sid",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_vlr_op_pri,
            { "Priority", "veloren.open.prio",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_vlr_op_prom,
            { "Promises", "veloren.open.promises",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_vlr_op_bandw,
            { "Bandwidth", "veloren.open.bandw",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
    // Header
        { &hf_vlr_hd_mid,
            { "MessageId", "veloren.dhdr.mid",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_vlr_hd_sid,
            { "StreamId", "veloren.dhdr.sid",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_vlr_hd_len,
            { "Length", "veloren.dhdr.len",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
    // Data
        { &hf_vlr_dt_mid,
            { "MessageId", "veloren.data.mid",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_vlr_dt_len,
            { "Length", "veloren.data.len",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_vlr_dt_data,
            { "Data", "veloren.data.data",
            FT_BYTES, ENC_SEP_SPACE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_vlr_dt_meaning,
            { "Parsed", "veloren.data.parsed",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
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
