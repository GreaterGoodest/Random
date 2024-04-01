global _start

section .text
_start: 
    xor rsi, rsi  ; null out rsi (arg2)
    xor rdx, rdx  ; null out rdx (arg3)
    push rsi    ; ensure null terminator at end of shell string
    mov rax, 59  ; -> execve syscall #
    mov rbx, 0x68732f2f6e69622f  ; /bin/sh\00 -> little endian

    ; push string onto stack then pop stack address back into rdi (arg1)
    push rbx
    push rsp
    pop rdi


    syscall  ; get shell
