#include <stdlib.h>
#include <stdio.h>

int main() {

  char * a = malloc(10);
  
  free(a+8);

}
