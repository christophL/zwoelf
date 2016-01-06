#pragma once

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

typedef struct {
    int fd;
    char* file_name;
    size_t file_size;
    void* mem;
    
} file_data;

file_data file_open(char* path);
void file_load(file_data* file);
void file_close(file_data* file);
