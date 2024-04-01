__attribute__ ((naked)) void _start()
{
    asm(
        ".intel_syntax;"
        "xor rsi, rsi;"
        "xor rdx, rdx;"
        "push rsi;"
        "mov rax, 59;"
        "mov rbx, 0x68732f2f6e69622f;"

        "push rbx;"
        "push rsp;"
        "pop rdi;"
        "syscall;"
    );
}