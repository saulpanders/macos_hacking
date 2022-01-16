//written to test MacOS address randomization post-Leopard
/*
This program prints out the address of the malloc() routine located within libSystem. It then prints out the address of a malloced heap buffer, of a stack buffer, and, finally, of a function from the application image. Running this pro- gram on one computer (even after reboots) always reveals the same numbers; however, running this program on different machines shows some differences in the output. 

from Mac Hackers Handbook

*/
#include <stdio.h>
#include <stdlib.h>
void foo(){ ;
}
int main(int argc, char *argv[]){
          int y;
          char *x = (char *) malloc(128);
          printf("Lib function: %08x, Heap: %08x, Stack: %08x, Binary: %08x\n", &malloc, x, &y, &foo);
}
