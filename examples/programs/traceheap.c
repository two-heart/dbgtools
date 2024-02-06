#include <stdio.h>
#include <stdlib.h>


int main(void) {
    void *p1 = malloc(0x80);
    void *p2 = malloc(0x20);

    free(p1);

    void *p3 = malloc(0x1000);

    free(p2);
    free(p3);

    return 0;
}
