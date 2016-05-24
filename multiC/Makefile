CC = gcc
CFLAGS = -Wall -g -std=gnu99 -I. -Iinclude \
				 -Ilocal/include/libbson-1.0 \
				 -Ilocal/include/libmongoc-1.0
LDFLAGS = -Llocal/lib
LDLIBS = -lpcap -lmongoc-1.0 -lbson-1.0
VPATH = src

.PHONY: all clean distclean setup check

all: setup main

setup:
	@if [ ! -d ./local ];then\
		echo 'Please run the configuration script (./configure) before'\
			'running the Makefile.';\
		exit 1;\
	fi

main: main.o packetHandle.o worker.o protocol.o optparser.o dns.o db.o

check:
	$(MAKE) -C tests

clean:
	rm -rf *.o main
	$(MAKE) clean -C tests

distclean: clean
	rm -rf local/ third_party/mongo-c-driver

debug: CFLAGS += -DDEBUG
debug: all

