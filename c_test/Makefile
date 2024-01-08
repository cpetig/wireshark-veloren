CFLAGS = -I../rust
LIBS= -L../rust/target/debug -lveloren_dissector -lm

test_dissect: test.c 
	$(CC) -o $@ $(CFLAGS) $^ $(LIBS)

clean:
	-rm test_dissect