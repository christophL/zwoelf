#include "file.h"

/**
 * Opens the file at the provided path.
 * Arguments:
 *   path: the file path to be opened
 * Returns: a struct containing file information (mapped address, file name, file size)
 */
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

/**
 * Loads an opened file into memory.
 * Since the file is loaded using mmap, changes to the mapped memory
 * will be reflected in the target file as well.
 * Arguments:
 *   file: the file to be loaded
 */
void file_load(file_data* file) {
    void* mem = mmap(NULL, file->file_size, PROT_READ | PROT_WRITE, MAP_SHARED, file->fd, 0);
    if(mem == MAP_FAILED) {
        perror("Could not load target file");
        exit(0);
    }
    file->mem = mem;
}

/**
 * Closes the provided file.
 * Arguments:
 *   file: the file to be closed
 */
void file_close(file_data* file) {
    if(close(file->fd) < 0) {
        perror("Could not close target file descriptor.");
    }   
    
    if(file->mem != NULL && file->mem != MAP_FAILED) {
        if(munmap(file->mem, file->file_size) < 0)
            perror("Could not unmap file memory.");
    }
}
