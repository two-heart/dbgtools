#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>


int prod(int a, int b) {
    return a*b;
}


typedef struct A {
    unsigned int x;
    unsigned int y;
} A;

typedef struct Test {
    char *data;
    double flt;
    bool b;
    A* a;
    int (*func_ptr)(int, int);
} Test;




int main() {
    char buf[0x10] = "AAAAAAABBBBBBBB";
    Test test;
    test.data = (char*) malloc(0x10);
    test.flt = 1.1;
    test.b = true;
    test.a = (A*)malloc(sizeof(A));
    test.a->x = 0x1337;
    test.a->y = 0x420;

    test.func_ptr = prod;

    memcpy(test.data, buf, 0x10);

    printf("test @ %p\n", &test);

    puts(test.data);
    printf("%lf\n", test.flt);

    return 0;
}
