#include "decrypt.h"
#include "file.h"

#define CMD_SIZE 500


/**
 * Opens the decrypter file and loads it into memory.
 * Arguments:
 *   prog_name: the program whose decrypter should be loaded.
 * Returns: a struct containing useful file information
 */
static file_data load_decrypter(char* prog_name) {
    char buf[60];
    snprintf(buf, 60, "decrypter_%s", prog_name);
    
    file_data ret = file_open(buf);
    file_load(&ret);
    return ret;
}

/**
 * Calls the decrypter-compilation script to set all addresses and sizes and obtain a decrypter in machine code.
 * Arguments:
 *   prog_name: the program for which the decryption code should be assembled
 *   start: the start of the .text section in the target program
 *   size: the size of the .text section in the target file
 *   entry: the entry-point address of the target program
 */
file_data decrypt_prepare(char* prog_name, void* start, size_t size, void* entry) {
    char cmd[CMD_SIZE];
    
    snprintf(cmd, CMD_SIZE, "./create_decrypter.sh %s %p 0x%lx %p", prog_name, start, size, entry);
    system(cmd);
    
    return load_decrypter(prog_name);
}