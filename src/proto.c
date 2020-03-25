#include <stdio.h>
#include <mcheck.h>
#include <stdlib.h>
#include <assert.h>

char* test()
{
    char *str = "Hello World";
    /*
    char *p;
    p = calloc(12, sizeof(char));
    assert(p);
    snprintf(p, 12, str);
    */
    return str;
}

int main()
{
    mtrace();
    char* p = test();
    return 0;
}
