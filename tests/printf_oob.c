#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main() {

  char * a = malloc(10);
  
  memset(a, 'a', 10);
  
  rawmemchr(a, 0);

}
