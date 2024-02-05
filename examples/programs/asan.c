#include <stdio.h>


void vuln(void) {
    char buf[0xff] = { 0 };
    buf[0x10] = 0x41;

    buf[0xff + 0x10] = 0x69;
}

int main(void) {
    vuln();
}
