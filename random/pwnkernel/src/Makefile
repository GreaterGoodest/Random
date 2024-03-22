# add more modules here!
obj-m = mydev.o
KERNEL_VERSION=5.4

all: 
	echo $(OBJECTS)
	make -C ../linux-$(KERNEL_VERSION) M=$(PWD) modules
	gcc interact.c -o interact -static

clean:
	make -C ../linux-$(KERNEL_VERSION) M=$(PWD) clean
	rm -f interact
