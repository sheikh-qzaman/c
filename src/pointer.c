#include <stdio.h>
#include <stdlib.h>
#include <mcheck.h>
#include <assert.h>

typedef struct
{
    char        *street;
    char        *city;
    int         zip;
} address;

typedef struct
{
    char        *name;
    address     *addr;
} person;

void test_trace();
void print_struct(void *v, void *arg);
person* create_person(char *name, char *street, char *city, int zip);

void print_struct(void *v, void *arg)
{
    person *p = (person*) v;
    printf("%s\n%s\n%s\n%d\n", p->name, p->addr->street, p->addr->city, p->addr->zip);
}

person* create_person(char *name, char *street, char *city, int zip)
{
    person      *p;
    address     *addr;

    p = calloc(1, sizeof(person));
    addr = calloc(1, sizeof(address));

    p->name = name;
    addr->street = street;
    addr->city = city;
    addr->zip = zip;
    p->addr = addr;
    
    return p;
}

int main (void)
{
    mtrace();

    return 0;

    //char*   name = calloc(1000, sizeof(char));
    char*   name = malloc(1000 * sizeof(char));
    name = "Welcome!";
    puts(name);
    
    person *p = create_person("Sheikh Umayer", "110 Kiely Blvd", "Santa Clara", 95051);
    print_struct(p, NULL);

    return 0;
}
