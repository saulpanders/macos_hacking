/*
testing stack execution of shellcode w/ mprotect

still works on Monterey!
https://craftware.xyz/tips/Stack-exec.html

*/


#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Infinite loop shellcode
char shellcode[] = "\xeb\xfe";

typedef int (*funcPtr)();

int main(int argc, char *argv[]){
    int (*f)();		// Function pointer
    char x[4];		// Stack variable

    //setting up memory to mark as executable
    unsigned long page_start;
    int ret;
    int page_size;

    page_size = sysconf(_SC_PAGE_SIZE);
    page_start = ((unsigned long) x) & 0xfffffffffffff000;
    printf("[*] page start: 0x%016lx\n", page_start);
    printf("[*] buff start: 0x%016lx\n", (unsigned long) x);

    //marking entire memory page RWX
    ret = mprotect((void *) page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);
    if(ret<0){
        perror("[-] mprotect failed");
    }

    // Copy shellcode on the stack
    memcpy(x, shellcode, sizeof(shellcode));

    // Cast to function pointer and execute
    f = (funcPtr)x;
    (*f)();
}