CC = gcc
CFLAGS = -Wall -I../include -g -std=gnu99
VPATH = ../src

# Test binaries have the form *_test to be caught by the gitignore.
PROGS = sample_test dnsHeader_test

.PHONY: all clean

# Compile and run all tests.
all: $(PROGS)
	@for arg in $(PROGS); do \
		cmd="./"$$arg; \
		$$cmd; \
	done

sample_test: test.o sample_test.o
dnsHeader_test: test.o dnsHeader_test.o dns.o

clean:
	rm -rf *.o $(PROGS)

