#include <veloren_dissector.h>

char const * const sinput2 = "\x6a\x1a\x00\x00\x00\x01\x00\x01\x00\xf0\x11\x01\x00\x00\x00\x04\x00\x00\x00\x53\x4d\x00\x00\x00\x4b\x00\x00\x00\xcf\x03\x00\x7e\x94\x0e\x40\x01\x00\x00\x00\x00\x00\x00\x00";
#define SINPUT2_LEN 43

int main() {
    result_handle dec3 = ingest_data(2, 1, sinput2, SINPUT2_LEN);
    printf("Short %s\n", get_short_representation(dec3));
    printf("Long  %s\n", get_long_text(dec3));
    free_handle(dec3);
    return 0;
}
