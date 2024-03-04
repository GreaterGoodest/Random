#include <stdlib.h>
#include <unistd.h>

int main()
{
    void* p = malloc(200);
    read(0, p, 500);
    free(p);
    free(p);
    return 0;
}