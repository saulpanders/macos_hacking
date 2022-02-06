/*
PoC for testing if the stack  is executable. Adapted from Mac Hackers Handbook/craftware.xyz

used to use a global var & memcpy from there into main().

Instead using a local stack_var (so its executable!)

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*funcPtr)();

int main(int argc, char *argv[]){
  
  //infinite loop shellcode
  char *stack_var ="\xeb\xfe";
  int(*f)();

  printf("[*] Stack Shellcode Addr: 0x%016lx\n", stack_var);


  printf("[+] Executing shellcode in a stack var..");
  f = (funcPtr)stack_var;
  (*f)();
}

