#include <stdlib.h>
#include <stdio.h>
#include <locale.h>

int main() {

  setlocale(LC_ALL, "Italian_Italy.1250"); 

  char * a = strdup("XXXXXXXXXXX");
  
  char * b = strdup("XXXXXXXXXXY");
  
  return strcmp(a, b);

}
