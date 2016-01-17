#include <stdio.h>
#include <stdlib.h>

#include "elf.h"

int main(int argc, char **argv) {
    if(argc != 3) {
        printf("usage: %s <ELF-File> <key>\n", argv[0]);
        return 0;
    }
    
    elf_file file = elf_open(argv[1]);
    elf_load(&file);
    elf_prepare(&file);
    elf_encrypt(&file, (uint8_t*)argv[2]);
    
    return 0;
}