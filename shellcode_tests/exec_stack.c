/*
PoC for testing if the stack  is executable. from Mac Hackers Handbook/craftware.xyz

used to use a global var & memcpy from there into main().

Instead using a local stack_var (so its executable)

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*funcPtr)();

int main(int argc, char *argv[]){
  int(*f)();

  char *stack_var ="\xeb\xfe";

  print("[+] Executing shellcode in a stack var..");
  f = (funcPtr)stack_var;
  (*f)();
}

