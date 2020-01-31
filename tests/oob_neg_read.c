#include <stdlib.h>
#include <stdio.h>

int main() {

  long * a = malloc(10);
  
  printf("%ld\n", a[-1]);
  
  free(a);

}
