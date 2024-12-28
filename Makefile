#WS_SOURCE=$(HOME)/Downloads/wireshark-4.0.8
DEPS=$(shell pkg-config --cflags wireshark)
CFLAGS=-g -fPIC  $(DEPS) -I. -Irust
#-I$(WS_SOURCE)/ -I$(WS_SOURCE)/obj-x86_64-linux-gnu/ -I$(WS_SOURCE)/include/ $(DEPS)
LDFLAGS=-shared
#$(shell pkg-config --ldflags wireshark)
LIBS=$(shell pkg-config --libs wireshark) -Lrust/target/debug -lveloren_dissector
WIRESHARK_VERSION=$(shell wireshark --version | sed -n -r 's/Wireshark ([0-9]\.[0-9]).*/\1/p')

all: rust/target/debug/libveloren_dissector.a veloren_ds.so

veloren_ds.so: plugin.c veloren.c
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LIBS)

install: all
	cp veloren_ds.so $(HOME)/.local/lib/wireshark/plugins/$(WIRESHARK_VERSION)/epan

uninstall:
	rm $(HOME)/.local/lib/wireshark/plugins/*/epan/veloren_ds.so

clean:
	rm -rf rust/target
	rm veloren_ds.so

rust/target/debug/libveloren_dissector.a:
	git submodule update --init --recursive
	cd rust && cargo build
