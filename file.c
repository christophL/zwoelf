#include "file.h"

file_data file_open(char* path) {
    file_data ret;
    if((ret.fd = open(path, O_RDWR, 0)) < 0) {
        perror("Could not open target file");
        exit(0);
    }
    
    struct stat file_stat;
    if(fstat(ret.fd, &file_stat) < 0) {
        perror("Could not obtain file information");
        exit(0);
    }
    ret.file_size = file_stat.st_size;
    ret.file_name = path;
    ret.mem = NULL;
    return ret;
}

void file_load(file_data* file) {
    void* mem = mmap(NULL, file->file_size, PROT_READ | PROT_WRITE, MAP_SHARED, file->fd, 0);
    if(mem == MAP_FAILED) {
        perror("Could not load target file");
        exit(0);
    }
    file->mem = mem;
}

void file_close(file_data* file) {
    if(close(file->fd) < 0) {
        perror("Could not close target file descriptor.");
    }   
    
    if(file->mem != NULL && file->mem != MAP_FAILED) {
        if(munmap(file->mem, file->file_size) < 0)
            perror("Could not unmap file memory.");
    }
}
