CC = gcc
CFLAGS = -Wall -Iinclude -g -std=gnu99
LDLIBS = -lpcap -lpthread
VPATH = src

.PHONY: all clean

all: main

main: main.o packetHandle.o worker.o protocol.o optparser.o

clean:
	rm -rf *.o main

debug: CFLAGS += -DDEBUG
debug: all

