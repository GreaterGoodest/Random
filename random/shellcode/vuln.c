#include <stdio.h>
#include <unistd.h>

int main()
{
    char buff[100] = {0};

    printf("stack leak: %p\n", buff);

    read(0, buff, 1024);  // Overflow
    
    return 0;
}