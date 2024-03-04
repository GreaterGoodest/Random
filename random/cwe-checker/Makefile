all: vuln.bin

CC=clang

vuln.bin: main.c
	$(CC) -o $@ $<	

check: vuln.bin
	docker run --rm -v ./vuln.bin:/input ghcr.io/fkie-cad/cwe_checker /input

clean:
	rm -f *.bin
 