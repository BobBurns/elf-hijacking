CC = gcc
CFLAGS = -Wall

all: relocate

relocate: reloc.o utils.o inject.o
	$(CC) -o relocate reloc.o utils.o inject.o

test:
	$(CC) $(CFLAGS) -c reloc.c utils.c inject.c

clean:
	rm -f reloc.o utils.o inject.o .zyx.tmp.bin .elfmod-bin 

