# Build this directory independently after installing cryptolib. The default
# executable uses the combined archive explicitly, so no runtime path is needed.
CC = cc
PREFIX ?= /usr/local
CFLAGS ?= -std=c11 -Wall -Wextra -O2
CPPFLAGS += -I"$(PREFIX)/include"
LIBDIR ?= $(PREFIX)/lib
SHARED_LIBS := -lsha3 -lsha256 -lmd5 -laes256 -larcfour

.PHONY: all clean
all: consumer
consumer: main.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $< "$(LIBDIR)/libcryptolib.a" -o $@ $(LDLIBS)
consumer-shared: main.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $< -L"$(LIBDIR)" $(SHARED_LIBS) -Wl,-rpath,"$(LIBDIR)" -o $@ $(LDLIBS)
clean:
	rm -f consumer consumer-shared
