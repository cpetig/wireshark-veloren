
typedef void *result_handle;

result_handle ingest_data(int stream, int from_server, unsigned char const* data, unsigned len);

void free_handle(result_handle);
// valid until free_handle
char const* get_short_representation(result_handle);
char const* get_long_text(result_handle);
