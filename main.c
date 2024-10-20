#include <stdio.h>
#include <string.h>
#include <time.h>
#include "Antivirus.h"
int main(int argc, char **argv)
{
    if (strcmp(argv[1], "scan") == 0)
    {
        scan(argv[2], 1);
    }
    else if (strcmp(argv[1], "inspect") == 0)
    {
        inspect(argv[2], 2);
    }
    else if (strcmp(argv[1], "monitor") == 0)
    {
        monitor(argv[2], 3);
    }
    else if (strcmp(argv[1], "slice") == 0)
    {
        time_t t;
         srand((unsigned) time(&t));
        slice(argv[2]);
    }
    else if (strcmp(argv[1], "unlock") == 0)
    {
        unlock(argv,argc-1);
    }
}