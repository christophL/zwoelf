#pragma once

#include <elf.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include "file.h"

typedef struct {
    file_data data;
    
    Elf64_Ehdr* ehdr;
    Elf64_Phdr* phdr_table;
    Elf64_Shdr* shdr_table;
    Elf64_Phdr* note;
    Elf64_Phdr* load_rw;
    Elf64_Shdr* text;
    Elf64_Shdr* bss;
    Elf64_Shdr* rela_dyn;
    Elf64_Shdr* dynsym;
} elf_file;


elf_file elf_open(char* path);
void elf_load(elf_file* file);
void elf_prepare(elf_file* file);
void elf_encrypt(elf_file* file);
void elf_close(elf_file* file);