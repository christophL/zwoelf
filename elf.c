#include "elf.h"
#include "encrypt.h"
#include "decrypt.h"
#include "file.h"

elf_file elf_open(char *path) {
    elf_file ret;
    ret.data = file_open(path);
    ret.ehdr = NULL;
    return ret;
}

void elf_load(elf_file *file) {
    file_load(&file->data);
    file->ehdr = file->data.mem;
}

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

static int is_exec(elf_file* file) {
    Elf64_Ehdr* header = file->ehdr;
    if(header->e_type != ET_EXEC) {
        printf("Error: target file is not an executable\n");
        return 0;
    }
    return 1;
}

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

void elf_prepare(elf_file* file) {
    if(!is_elf64(file)) return;
    if(!is_exec(file)) return;
    file->shdr_table = file->data.mem + file->ehdr->e_shoff;
    file->phdr_table = file->data.mem + file->ehdr->e_phoff;
    if(!find_text_section(file)) return;
    if(!find_note_segment(file)) return;
    set_code_writable(file);
}

static void inject_decrypter(elf_file* file) {
    void* dst_addr = file->data.mem + file->note->p_offset;
    void* code_start = (void*)file->text->sh_addr;
    size_t code_size = file->text->sh_size;
    void* ent_point = (void*)file->ehdr->e_entry;
    file_data decrypter = decrypt_prepare(file->data.file_name, 
                                          code_start, code_size, ent_point);
    
    memcpy(dst_addr, decrypter.mem, decrypter.file_size);
    if(file->note->p_filesz < decrypter.file_size) {
        printf("Warning: decryption code does not fit into NOTE segment, program will probably not run.\n");
        file->note->p_filesz = decrypter.file_size;
        file->note->p_memsz = decrypter.file_size;
    }
    file->ehdr->e_entry = file->note->p_vaddr;
    file_close(&decrypter);
    printf("Decryption code injected into NOTE segment.\n");
}

void elf_encrypt(elf_file* file) {
    if(file->text == NULL) {
        printf("Error: text section not loaded, file needs to be parsed first.\n");
        return;
    }
    
    uint8_t* start = file->data.mem + file->text->sh_offset;
    size_t size = file->text->sh_size;
    encrypt_xor(start, size, 123);
    inject_decrypter(file);
    printf("Done.\n");
}


void elf_close(elf_file* file) {
     file_close(&file->data);
}



