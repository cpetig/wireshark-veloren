#WS_SOURCE=$(HOME)/Downloads/wireshark-4.0.8
DEPS=$(shell pkg-config --cflags wireshark)
CFLAGS=-g -fPIC  $(DEPS) -I.
#-I$(WS_SOURCE)/ -I$(WS_SOURCE)/obj-x86_64-linux-gnu/ -I$(WS_SOURCE)/include/ $(DEPS)
LDFLAGS=-shared 
#$(shell pkg-config --ldflags wireshark)
LIBS=$(shell pkg-config --libs wireshark)

veloren_ds.so: plugin.c veloren.c
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LIBS)

install: veloren_ds.so
	cp $^ $(HOME)/.local/lib/wireshark/plugins/4.0/epan
