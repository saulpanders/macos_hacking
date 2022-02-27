/*
from mac hackers handbook. Explicitly setting heap to exec - still doesnt work!
*/
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

//infinite loop
char shellcode[] = "\xeb\xfe";

typedef int (*funcPtr)();

int main(int argc, char *argv[]){

  unsigned long page_start;
  int page_size;

  page_size = sysconf(_SC_PAGE_SIZE);

  char *heap_buff = malloc(2);



  if (page_size == -1)
    perror("[-] sysconf failed");
  else
    printf("[+] page size: %d\n", page_size);

  printf("[*] sizeof pointer: %lu\n" ,sizeof(void*));
  printf("[*] sizeof int: %lu\n" ,sizeof(unsigned int));
  printf("[*] sizeof long: %lu\n", sizeof(unsigned long));

  page_start = ((unsigned long) heap_buff)& 0xfffffffffffff000;


  printf("[+] page start: 0x%016lx\n", (unsigned long)  page_start);
  printf("[+] buff start: 0x%016lx\n", (unsigned long) heap_buff);



  int ret = mprotect((void *) page_start, page_size, PROT_WRITE | PROT_READ | PROT_EXEC);
  if(ret<0){ perror("[-] mprotect failed"); }

  memcpy(heap_buff, shellcode, sizeof(shellcode));

  int(*f)();
  f = (funcPtr)heap_buff;
  (*f)();  
}
