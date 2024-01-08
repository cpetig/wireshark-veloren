#include <stdio.h>
#include <veloren_dissector.h>

char const * const sinput2 = "\x6a\x1a\x00\x00\x00\x01\x00\x01\x00\xf0\x11\x01\x00\x00\x00\x04\x00\x00\x00\x53\x4d\x00\x00\x00\x4b\x00\x00\x00\xcf\x03\x00\x7e\x94\x0e\x40\x01\x00\x00\x00\x00\x00\x00\x00";
#define SINPUT2_LEN 43

char const cinput1[] = {
    0x2b, 0x06, 0x00, 0x01, 0x00, 0xe0, 0xe1, 0xbb, 0x27, 0x38, 0x38, 0xf6, 0x82, 0x3a, 0xf8, 0xff,
    0x7f, 0x3f, 0x00, 0x00,
};
#define CINPUT1_LEN 20

char const ping[] = { 1,0,0,0 };
#define PING_LEN 4

int main() {
    result_handle dec3 = ingest_data(2, 1, sinput2, SINPUT2_LEN);
    printf("Short %s\n", get_short_representation(dec3));
    printf("Long  %s\n", get_long_text(dec3));
    free_handle(dec3);

    dec3 = ingest_data(2, 0, cinput1, CINPUT1_LEN);
    printf("Short %s\n", get_short_representation(dec3));
    printf("Long  %s\n", get_long_text(dec3));
    free_handle(dec3);

    dec3 = ingest_data(1, 0, ping, PING_LEN);
    printf("Short %s\n", get_short_representation(dec3));
    printf("Long  %s\n", get_long_text(dec3));
    free_handle(dec3);
    return 0;
}
