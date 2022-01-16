/*

shellcode runner for OSX - we make sure to save the shellcode in the .text section (so its executable by default)
https://craftware.xyz/tips/Shellcode-MacOS-64.html
*/


const char sc[] __attribute__((section("__TEXT,__text"))) = "\xeb\x1e\x5e\xb8\x04\x00\x00\x02\xbf\x01\x00\x00\x00\xba\x0e\x00\x00\x00\x0f\x05\xb8\x01\x00\x00\x02\xbf\x00\x00\x00\x00\x0f\x05\xe8\xdd\xff\xff\xff\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64\x21\x0d\x0a";

typedef int (*funcPtr)();
int main(int argc, char **argv)
{
    funcPtr func = (funcPtr) sc;
    (*func)();

    return 0;
}