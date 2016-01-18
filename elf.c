#include "elf.h"
#include "encrypt.h"
#include "decrypt.h"
#include "file.h"

/**
 * Opens the ELF file at the provided path.
 * Returns: a struct containing information useful for encrypting the file
 */
elf_file elf_open(char *path) {
    elf_file ret;
    ret.data = file_open(path);
    ret.ehdr = NULL;
    return ret;
}

/**
 * Loads the provided ELF file into memory
 * Arguments:
 *   file: the file to be loaded
 */
void elf_load(elf_file *file) {
    file_load(&file->data);
    file->ehdr = file->data.mem;
}

/**
 * Checks if the provided file is a 64Bit ELF file
 * Arguments:
 *   file: the file to check
 * Returns: true iff the file is a 64Bit ELF file
 */
static int is_elf64(elf_file *file) {
    Elf64_Ehdr *header = file->ehdr;
    if(header->e_ident[EI_MAG0] != ELFMAG0 || 
            header->e_ident[EI_MAG1] != ELFMAG1 ||
            header->e_ident[EI_MAG2] != ELFMAG2 ||
            header->e_ident[EI_MAG3] != ELFMAG3 ||
            header->e_ident[EI_CLASS] != ELFCLASS64) {
        printf("Error: target file is not an ELF64 file\n");
        return 0;
    }
    return 1;
}

/**
 * Checks if the provided file is an executable ELF file
 * (not a shared library).
 * Arguments:
 *   file: the file to check
 * Returns: true iff the file is executable
 */
static int is_exec(elf_file* file) {
    Elf64_Ehdr* header = file->ehdr;
    if(header->e_type != ET_EXEC) {
        printf("Error: target file is not an executable\n");
        return 0;
    }
    return 1;
}

/**
 * Searches the section header table of the provided file for its .text section.
 * The section headers need to be obtained from the section header string table
 * (each section header contains an index into this string table).
 * The section is searched by iterating through the section header table of the file
 * and looking up each section's name in the section header string table.
 * Arguments:
 *   file: the ELF file to search
 * Returns: true iff the text section was found
 */
static int find_text_section(elf_file *file) {
    Elf64_Shdr* shdr_str_table = &file->shdr_table[file->ehdr->e_shstrndx];
    char* sh_strings = file->data.mem + shdr_str_table->sh_offset;
    
    for(int i = 0; i < file->ehdr->e_shnum; i++) {
        Elf64_Shdr* header = &file->shdr_table[i];
        char* section_name = sh_strings + header->sh_name;
        
        if(strncmp(".text", section_name, 5) == 0) {
            file->text = header;
            printf("Text section found.\n");
            return 1;
        }
    }
    printf("Error: Text section not found.\n");
    return 0;
}

/**
 * Searches the provided file for a NOTE segment and sets the memory
 * protection of the segment to writable.
 * The segment is searched by iterating through the program header
 * table of the file.
 * Arguments:
 *   file: the ELF file in which to search for a NOTE segment
 * Returns: true iff the NOTE segment was found
 */
static int find_note_segment(elf_file* file) {
    int phnum = file->ehdr->e_phnum;
    for(int i = 0; i < phnum; i++) {
        Elf64_Phdr* header = &file->phdr_table[i];
        if(header->p_type == PT_NOTE) {
            header->p_flags |= PF_X;
            file->note = header;
            printf("Found Note segment.\n");
            return 1;
        }
    }
    printf("Error: Note segment not found.\n");
    return 0;
}

/**
 * Changes the memory protection of the code segment of the provided ELF file
 * to allow write operations.
 * (Required for runtime-decryption of the code)
 * Arguments:
 *   file: the ELF file whose code segment should be made writable
 */
static void set_code_writable(elf_file* file) {
    int phnum = file->ehdr->e_phnum;
    for(int i = 0; i < phnum; i++) {
        Elf64_Phdr* header = &file->phdr_table[i];
        if(header->p_type == PT_LOAD && (header->p_flags & PF_X) != 0) {
            header->p_flags |= PF_W;
            printf("Set code segment writable.\n");
            return;
        }
    }
}

/**
 * Modifies the NOTE segment of the provided file.
 * The segment is changed to a LOAD segment and pointed at the end of the file
 * (the location where the decryption code will be added to).
 * During program loading, the decryption code will be loaded to a memory address
 * that is much higher than the address of typical program components.
 */
static void modify_note(elf_file* file, size_t decrypt_size) {
    file->note->p_type = PT_LOAD;
    file->note->p_flags |= PF_X;
    file->note->p_offset = file->data.file_size;
    file->note->p_vaddr = file->note->p_paddr = 0x6000000 + file->note->p_offset;
    file->note->p_filesz = file->note->p_memsz = decrypt_size;
    file->note->p_align = 0x1000;
}

/**
 * Parse the provided ELF file and load all information required for encrypting it.
 * Arguments:
 *   file: the ELF file to be parsed
 */
void elf_prepare(elf_file* file) {
    if(!is_elf64(file)) return;
    if(!is_exec(file)) return;
    file->shdr_table = file->data.mem + file->ehdr->e_shoff;
    file->phdr_table = file->data.mem + file->ehdr->e_phoff;
    if(!find_text_section(file)) return;
    if(!find_note_segment(file)) return;
    set_code_writable(file);
}

/**
 * Append the decryption code to the provided ELF file.
 * Arguments:
 *   file: the ELF file onto which the code should be appended
 *   decrypter: the file containing the decryption machine code
 */
static void append_decrypter(elf_file* file, file_data* decrypter) {
    int fd = open(file->data.file_name, O_APPEND|O_RDWR, 0);
    write(fd, decrypter->mem, decrypter->file_size);
    close(fd);
}

/**
 * Appends the decryption code to the provided file and changes the
 * NOTE segment to a LOAD segment that loads the decryption code.
 * Arguments:
 *   file: the file into which the decryption code should be injected
 */
static void inject_decrypter(elf_file* file) {
    void* code_start = (void*)file->text->sh_addr;
    size_t code_size = file->text->sh_size;
    void* ent_point = (void*)file->ehdr->e_entry;
    file_data decrypter = decrypt_prepare(file->data.file_name, 
                                          code_start, code_size, ent_point);
    
    modify_note(file, decrypter.file_size);
    file->ehdr->e_entry = file->note->p_vaddr;
    
    elf_close(file);
    append_decrypter(file, &decrypter);
    file_close(&decrypter);
    printf("Decryption code appended to file.\n");
}

/**
 * Encrypts the provided elf file using the provided key and
 * injects the decryption code.
 * Arguments:
 *   file: the file to encrypt
 *   key:  the encryption key to use
 */
void elf_encrypt(elf_file* file, uint8_t* key) {
    if(file->text == NULL) {
        printf("Error: text section not loaded, file needs to be parsed first.\n");
        return;
    }
    
    uint8_t* start = file->data.mem + file->text->sh_offset;
    size_t size = file->text->sh_size;
    encrypt_rc4(start, size, key);
    inject_decrypter(file);
    printf("Done.\n");
}


/**
 * Close the file descriptor associated with the provided ELF file
 * Arguments:
 *   file: the file to be closed
 */
void elf_close(elf_file* file) {
     file_close(&file->data);
}



