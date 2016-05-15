CC = gcc
CFLAGS = -Wall -Iinclude -Ilocal/include/libbson-1.0 \
				 -Ilocal/include/libmongoc-1.0 -g -std=gnu99
LDFLAGS = -Llocal/lib
LDLIBS = -lpcap -lmongoc-1.0 -lbson-1.0
VPATH = src

.PHONY: all clean distclean setup

all: setup main

setup:
	@if [ ! -d ./local ];then\
		echo 'Please run the configuration script (./configure) before'\
			'running the Makefile.';\
		exit 1;\
	fi

main: main.o packetHandle.o worker.o protocol.o optparser.o

clean:
	rm -rf *.o main

distclean: clean
	rm -rf local/ third_party/mongo-c-driver

debug: CFLAGS += -DDEBUG
debug: all

