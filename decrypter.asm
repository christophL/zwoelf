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

push rbp
mov rax,0x4028a0         ;the start of the code section
xor rcx, rcx
loop:
    xor byte [rax+rcx], dl
    inc rcx
    cmp rcx,0xff09      ;the size of the code section to decrypt
    jne loop
pop rbp
xor rdx, rdx                ;not resetting this causes a segfault
mov rax,0x404840
jmp rax        ;the original return address