CC = gcc
CFLAGS = -Wall -I../include
VPATH = ../src

PROGS = sample_test

.PHONY: all clean

# Compile and run all tests.
all: $(PROGS)
	@for arg in $(PROGS); do \
		cmd="./"$$arg; \
		$$cmd; \
	done

sample_test: test.o sample_test.o

clean:
	rm -rf *.o $(PROGS)

