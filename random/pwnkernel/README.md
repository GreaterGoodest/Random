# Summary 

This is a basic example of a character device. I used pwn college's environment to bootstrap this.

Build binaries:

```
cd src && make
```

Build and launch environment:


```
$ ./build.sh
```

Running the kernel:

```
$ ./launch.sh
```

insmod mydev.ko to create the device, then use ./interact to write to it and then read back out what was written.