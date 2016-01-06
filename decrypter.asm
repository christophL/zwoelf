BITS 64

store_first_arg:
    mov rcx, qword [rsp+0x10]   ;the address of the first command line argument
    mov dl, byte [rcx]          ;the first command line argument


push rbp
mov rax,###start###         ;the start of the code section
xor rcx, rcx
loop:
    xor byte [rax+rcx], dl
    inc rcx
    cmp rcx,###size###      ;the size of the code section to decrypt
    jne loop
pop rbp
xor rdx, rdx                ;not resetting this causes a segfault
mov rax,###return###
jmp rax        ;the original return address