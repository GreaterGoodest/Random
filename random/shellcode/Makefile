all: vuln exec c_shellcode

vuln: vuln.c
	clang $< -o $@ -fno-stack-protector -z execstack -nopie

exec: exec.asm
	nasm -f elf64 $< -o exec.o
	ld exec.o -o $@

c_shellcode: c_shellcode.c
	clang $< -o $@ -nostdlib

clean:
	rm -f vuln exec.o exec