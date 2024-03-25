all: logbook
CFLAGS := -Wl,-z,norelro -no-pie -g

logbook: Overflow-Object.cpp
	g++ -o $@ $< $(CFLAGS)

clean:
	rm -rf logbook
