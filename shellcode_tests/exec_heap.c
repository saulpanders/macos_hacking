/*
PoC for testing if the heap is executable. Adapted from Mac Hackers Handbook

Not working on Monterey!

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//shellcode creates an infinite loop (jump self)
char shellcode[] = "\xeb\xfe";

typedef int (*funcPtr)();

int main(int argc, char *argv[]){

  //declare space for shellcode on heap & check address of buffer
  char * heap_buff= (char *)malloc(2);
  printf("[*] heap Shellcode Buff: 0x%016lx\n", (unsigned long)heap_buff);


  //added a useless scanf as a breakpoint - for vmmap debugging
  char* breakpoint;
  scanf(breakpoint);

  
  //attempting to execute shellcode on heap through func pointer dereference - no good!
  int(*f)();
  memcpy(heap_buff, shellcode, sizeof(shellcode));
  f = (funcPtr)heap_buff;
  (*f)();

}
