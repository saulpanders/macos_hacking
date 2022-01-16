/*
PoC for testing if the heap is executable. from Mac Hackers Handbook

Not working on Monterey

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char shellcode[] = "\xeb\xfe";
int main(int argc, char *argv[]){
  void (*f)();
  char *x = malloc(2);
  memcpy(x, shellcode, sizeof(shellcode));
  f = (void (*)()) x;
  f();
}
