CC=clang

.PHONY: clean

all: loop_decide.bin

loop_decide.bin: loop_decide.c
	$(CC) $< -o $@ -g -O0

clean:
	rm -f loop_decide.bin