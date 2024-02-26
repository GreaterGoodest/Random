#include <stdio.h>
#include <unistd.h>

void loop_print()
{
    sleep(2);
    puts("Trapped...");
}

int main()
{
    int loop_switch = 0;

    while (loop_switch == 0)
    {
        loop_print();
    }

    puts("Escape!");
}