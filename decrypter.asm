BITS 64

store_last_arg:
    mov rax, qword [rsp]           ;argc
    rol rax, 0x3
    mov rdi, qword [rsp+rax]    ;the address of the last command line argument

remove_last_arg:
    mov qword [rsp+rax], 0x0
    mov al, byte [rsp]
    dec al
    mov byte [rsp], al

decrypt:
    push   rbp
    mov    rbp,rsp
    sub    rsp,0xc0
    mov    QWORD [rbp-0x138],rdi
    mov    QWORD [rbp-0x20],###start###
    mov    QWORD [rbp-0x28],###size###
    mov    QWORD [rbp-0x18],0x0
    jmp    label1
label2:
    add    QWORD [rbp-0x18],0x1
label1:
    mov    rdx,QWORD [rbp-0x138]
    mov    rax,QWORD [rbp-0x18]
    add    rax,rdx
    movzx  eax,BYTE [rax]
    test   al,al
    jne    label2
    mov    DWORD [rbp-0x4],0x0
    jmp    label3
label4:
    mov    eax,DWORD [rbp-0x4]
    mov    edx,eax
    mov    eax,DWORD [rbp-0x4]
    mov    BYTE [rbp+rax*1-0x130],dl
    add    DWORD [rbp-0x4],0x1
label3:       
    cmp    DWORD [rbp-0x4],0xff
    jbe    label4
    mov    DWORD [rbp-0x8],0x0
    mov    DWORD [rbp-0x4],0x0
    jmp    label5
label6:
    mov    eax,DWORD [rbp-0x4]
    movzx  eax,BYTE [rbp+rax*1-0x130]
    movzx  edx,al
    mov    eax,DWORD  [rbp-0x8]
    lea    ecx,[rdx+rax*1]
    mov    eax,DWORD  [rbp-0x4]
    mov    edx,0x0
    div    QWORD [rbp-0x18]
    mov    rax,QWORD [rbp-0x138]
    add    rax,rdx
    movzx  eax,BYTE [rax]
    movzx  eax,al
    add    eax,ecx
    and    eax,0xff
    mov    DWORD [rbp-0x8],eax
    mov    eax,DWORD [rbp-0x4]
    movzx  eax,BYTE [rbp+rax*1-0x130]
    mov    BYTE [rbp-0x29],al
    mov    eax,DWORD [rbp-0x8]
    movzx  edx,BYTE [rbp+rax*1-0x130]
    mov    eax,DWORD [rbp-0x4]
    mov    BYTE [rbp+rax*1-0x130],dl
    mov    eax,DWORD [rbp-0x8]
    movzx  edx,BYTE [rbp-0x29]
    mov    BYTE [rbp+rax*1-0x130],dl
    add    DWORD [rbp-0x4],0x1
label5:
    cmp    DWORD [rbp-0x4],0xff
    jbe    label6
    mov    DWORD [rbp-0x4],0x0
    mov    DWORD [rbp-0x8],0x0
    mov    DWORD [rbp-0xc],0x0
    jmp    label7
label8:
    mov    eax,DWORD [rbp-0x4]
    add    eax,0x1
    and    eax,0xff
    mov    DWORD [rbp-0x4],eax
    mov    eax,DWORD [rbp-0x4]
    movzx  eax,BYTE [rbp+rax*1-0x130]
    movzx  edx,al
    mov    eax,DWORD [rbp-0x8]
    add    eax,edx
    and    eax,0xff
    mov    DWORD [rbp-0x8],eax
    mov    eax,DWORD [rbp-0x4]
    movzx  eax,BYTE [rbp+rax*1-0x130] 
    mov    BYTE [rbp-0x2a],al
    mov    eax,DWORD [rbp-0x8]
    movzx  edx,BYTE [rbp+rax*1-0x130]
    mov    eax,DWORD [rbp-0x4]
    mov    BYTE [rbp+rax*1-0x130],dl
    mov    eax,DWORD [rbp-0x8]
    movzx  edx,BYTE [rbp-0x2a]
    mov    BYTE [rbp+rax*1-0x130],dl
    mov    eax,DWORD [rbp-0x4]
    movzx  edx,BYTE [rbp+rax*1-0x130]
    mov    eax,DWORD [rbp-0x8]
    movzx  eax,BYTE [rbp+rax*1-0x130]
    add    eax,edx
    mov    BYTE [rbp-0x2b],al
    mov    edx,DWORD [rbp-0xc]
    mov    rax,QWORD [rbp-0x20]
    add    rdx,rax
    mov    ecx,DWORD [rbp-0xc]
    mov    rax,QWORD [rbp-0x20]
    add    rax,rcx
    movzx  ecx,BYTE [rax]
    movzx  eax,BYTE [rbp-0x2b]
    cdqe   
    movzx  eax,BYTE [rbp+rax*1-0x130]
    xor    eax,ecx
    mov    BYTE [rdx],al
    add    DWORD [rbp-0xc],0x1
label7:
    mov    eax,DWORD [rbp-0xc]
    cmp    rax,QWORD [rbp-0x28]
    jb     label8
    nop
    leave
    xor    rdx,rdx
    xor    rdi,rdi
    mov    rax, ###return###
    jmp    rax