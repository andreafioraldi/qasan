#include <stdlib.h>
#include <stdio.h>

int main() {

  char * a = malloc(10);
  
  char * b = malloc(10);
  
  b[9] = 'a';
  
  free(a);
  
  free(b);
  
  free(a);

}
