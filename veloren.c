#include "config.h"
#include <epan/packet.h>
#include <epan/dissectors/packet-tcp.h>

#define FOO_PORT 14004

static int proto_foo;
static dissector_handle_t foo_handle;

#define FRAME_HEADER_LEN 11

#define HANDSHAKE 1
#define INIT 2
#define OPEN_STREAM 4
#define DATA_HEADER 6
#define DATA 7
#define RAW 8

/* This method dissects fully reassembled messages */
static int
dissect_foo_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
    /* TODO: implement your dissecting code */
    return tvb_captured_length(tvb);
}

/* determine PDU length of protocol foo */
static unsigned
get_foo_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    uint8_t type = tvb_get_guint8(tvb, offset);
//    ((uint8_t const*)data)[offset];
    if (type == HANDSHAKE) return 1+7+3*4; // - FRAME_HEADER_LEN;
    else if (type == INIT) return 1+16+16;
    else if (type == OPEN_STREAM) return 1+8+1+1+8;
    else if (type == DATA_HEADER) return 1+8+8+8;
    else if (type == DATA) return 1+8+2 + tvb_get_letohs(tvb, offset+9);
    //(unsigned)tvb_get_ntohl(tvb, offset+4)
//    *((uint16_t const*)(data+offset+9));
    else return 1;
}

static int
dissect_foo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "VLR");
    /* Clear the info column */
    col_clear(pinfo->cinfo,COL_INFO);
#if 0

    proto_item *ti = proto_tree_add_item(tree, proto_foo, tvb, 0, -1, ENC_LITTLE_ENDIAN);
#endif
    tcp_dissect_pdus(tvb, pinfo, tree, true, FRAME_HEADER_LEN,
                     get_foo_message_len, dissect_foo_message, data);
    return tvb_captured_length(tvb);
}

void
proto_register_foo(void)
{
    proto_foo = proto_register_protocol (
        "Veloren Protocol", /* name        */
        "VLR",          /* short name  */
        "vlr"           /* filter_name */
        );
    // foo_handle = create_dissector_handle(dissect_foo, proto_foo);
    // register_postdissector(foo_handle);
}

void
proto_reg_handoff_foo(void)
{

    foo_handle = create_dissector_handle(dissect_foo, proto_foo);
    dissector_add_uint_with_preference("tcp.port", FOO_PORT, foo_handle);
}
