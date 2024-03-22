#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#define BUFSIZE 256

int main()
{
    int fd = -1;
    char buff[BUFSIZE] = {0};

    fd = open("/proc/mydev", O_RDWR);
    if (fd < 0)
    {
        perror("open: ");
        return 1;
    }

    write(fd, "test", 4);
    puts("Wrote to buff");

    read(fd, buff, BUFSIZE);
    printf("buff contents: %s\n", buff);

    close(fd);
}