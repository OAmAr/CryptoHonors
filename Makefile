# Compiler, flags, etc.
CC = gcc
DEBUG = -g -O2
WFLAGS = -ansi -Wall -Wsign-compare -Wchar-subscripts -Werror
LDFLAGS = -Wl,-rpath,/usr/lib

# Libraries against which the object file for each utility should be linked
INCLUDES = /usr/include/
LIBS = /usr/lib/ 
DCRYPTINCLUDE = ../libdcrypt-0.6/
DCRYPTLIB = ../libdcrypt-0.6/
DMALLOC = #-ldmalloc
GMP = -lgmp
DCRYPT = -ldcrypt

# The source file(s) for each program
all: pv_keygen pv_encrypt pv_decrypt
test: all
	./test.sh
	make clean;
pv_misc.o : pv_misc.c pv.h
	$(CC) $(DEBUG) $(WFLAGS) -I. -I$(INCLUDES) -I$(DCRYPTINCLUDE) -c pv_misc.c

pv_keygen.o  : pv_keygen.c pv_misc.c pv.h
	$(CC) $(DEBUG) $(WFLAGS) -I. -I$(INCLUDES) -I$(DCRYPTINCLUDE) -c pv_keygen.c pv_misc.c

pv_encrypt.o : pv_encrypt.c pv_misc.c pv.h
	$(CC) $(DEBUG) $(WFLAGS) -I. -I$(INCLUDES) -I$(DCRYPTINCLUDE) -c pv_encrypt.c pv_misc.c

pv_decrypt.o : pv_decrypt.c pv_misc.c pv.h
	$(CC) $(DEBUG) $(WFLAGS) -I. -I$(INCLUDES) -I$(DCRYPTINCLUDE) -c pv_decrypt.c pv_misc.c

pv_keygen: pv_keygen.o pv_misc.o
	$(CC) $(DEBUG) $(WFLAGS) -o $@ $@.o pv_misc.o -L. -L$(LIBS) -L$(DCRYPTLIB) $(DCRYPT) $(DMALLOC) $(GMP)

pv_encrypt: pv_encrypt.o pv_misc.o
	$(CC) $(DEBUG) $(WFLAGS) -o $@ $@.o pv_misc.o -L. -L$(LIBS) -L$(DCRYPTLIB) $(DCRYPT) $(DMALLOC) $(GMP)

pv_decrypt: pv_decrypt.o pv_misc.o
	$(CC) $(DEBUG) $(WFLAGS) -o $@ $@.o pv_misc.o -L. -L$(LIBS) -L$(DCRYPTLIB) $(DCRYPT) $(DMALLOC) $(GMP)

clean:
	rm -f core *.core *.o pv_encrypt pv_decrypt pv_keygen  *~

.PHONY: all clean test
