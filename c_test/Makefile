CFLAGS = -I../rust
LIBS= -L../rust/target/debug -lveloren_dissector

test_dissect: test.c 
	$(CC) -o $@ $(CFLAGS) $^ $(LIBS)
