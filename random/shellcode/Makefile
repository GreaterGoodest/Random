all: vuln exec

vuln: vuln.c
	clang $< -o $@ -fno-stack-protector -z execstack -nopie

exec: exec.asm
	nasm -f elf64 $< -o exec.o
	ld exec.o -o $@

clean:
	rm -f vuln exec.o exec