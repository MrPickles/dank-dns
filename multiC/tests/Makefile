CC = gcc
CFLAGS = -Wall -I../include -g -std=gnu99 \
				 -I../local/include/libbson-1.0 \
				 -I../local/include/libmongoc-1.0
LDFLAGS = -L../local/lib
LDLIBS = -lmongoc-1.0 -lbson-1.0
VPATH = ../src

# Test binaries have the form *_test to be caught by the gitignore.
PROGS = sample_test dnsHeader_test mongo_test

.PHONY: all clean

# Compile and run all tests.
all: $(PROGS)
	@for arg in $(PROGS); do \
		cmd="./"$$arg; \
		$$cmd; \
	done

sample_test: test.o sample_test.o
dnsHeader_test: test.o dnsHeader_test.o dns.o
mongo_test: test.o mongo_test.o

clean:
	rm -rf *.o $(PROGS)

