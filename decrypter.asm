BITS 64

store_last_arg:
    mov rax, qword [rsp]           ;argc
    rol rax, 0x3
    mov rcx, qword [rsp+rax]    ;the address of the last command line argument
    mov dl, byte [rcx]          ;the last command line argument
    mov qword [rsp+rax], 0x0
    mov al, byte [rsp]
    dec al
    mov byte [rsp], al

mov rax,###start###         ;the start of the code section
xor rcx, rcx
loop:
    xor byte [rax+rcx], dl
    inc rcx
    cmp rcx,###size###      ;the size of the code section to decrypt
    jne loop
xor rdx, rdx                ;not resetting this causes a segfault
xor rax, rax
mov rbp,###return###
jmp rbp       ;the original return address