CC=gcc
CFLAGS=-g3 -Wall -Wextra -D_GNU_SOURCE
LDFLAGS=
SRC=main.c elf.c encrypt.c decrypt.c file.c
HDR=elf.h encrypt.h decrypt.h file.h


crypter: $(SRC) $(HDR)
	$(CC) $(LDFLAGS) $(SRC) $(CFLAGS) -o crypter
	

.PHONY: clean

clean:
	rm -f crypter
	rm -f decrypter_*