all: logbook
CFLAGS := -Wl,-z,norelro -no-pie

logbook: UAF-Object.cpp
	g++ -o $@ $< $(CFLAGS)

clean:
	rm -rf logbook
