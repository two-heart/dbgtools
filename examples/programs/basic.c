#include <stdio.h>
#include <unistd.h>

int main() {
  int a = 42;
  int b = 0;
  b += a;
  printf("%d\n", b);
  char v;
  read(0, &v, 1);
  return 0;
}
