#include "decrypt.h"
#include "file.h"

#define CMD_SIZE 500

static file_data load_decrypter(char* prog_name) {
    char buf[60];
    snprintf(buf, 60, "decrypter_%s", prog_name);
    
    file_data ret = file_open(buf);
    file_load(&ret);
    return ret;
}

file_data decrypt_prepare(char* prog_name, void* start, size_t size, void* entry) {
    char cmd[CMD_SIZE];
    
    snprintf(cmd, CMD_SIZE, "./create_decrypter.sh %s %p 0x%lx %p", prog_name, start, size, entry);
    system(cmd);
    
    return load_decrypter(prog_name);
}