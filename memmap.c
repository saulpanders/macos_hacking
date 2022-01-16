/*
https://craftware.xyz/tips/Inspect-virtual-memory.html

understanding process virtual memory on OSX with vmmap

vmmap command can be used to view the memory layout of a process.
vmmap shows the region names, address ranges, permissions (current and maximum), and region details, which include the name of the backing file.
The example below, taken from Mac OS X and iOS Internals: To the Apple’s Core (2013), prints the address of different memory locations which we’ll correlate with with the output of vmmap.


vmmap --interleaved <

*/

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int global_j;
const int ci = 24;

int main (int argc, char **argv)
{
    int local_stack = 0;
    
    char *const_data = "This data is constant";
    char *tiny = malloc (32);            /* allocate 32 bytes */
    char *small = malloc (2*1024);       /* Allocate 2K */
    char *large = malloc (1*1024*1024);  /* Allocate 1MB */
    
    printf ("Text is %p\n", main);
    printf ("Global Data is %p\n", &global_j);
    printf ("Local (Stack) is %p\n", &local_stack);
    printf ("Constant data is %p\n", &ci );
    printf ("Hardcoded string (also constant) are at %p\n", const_data );
    printf ("Tiny allocations from %p\n", tiny );
    printf ("Small allocations from %p\n", small );
    printf ("Large allocations from %p\n", large );
    printf ("Malloc (i.e. libSystem) is at %p\n", malloc );
    
    sleep(100); /* so we can use vmmap on this process before it exits */
}