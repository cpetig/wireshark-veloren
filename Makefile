CFLAGS=-g -fPIC 
LDFLAGS=-shared
LIBS=

libveloren_ds.so: plugin.c
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LIBS)
