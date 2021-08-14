---
title: "Reversing 100 Binaries for Fun and Regret"
categories: ["Hacking", "Reversing", "Binary Exploitation"]
tags: ["hacking", "pentesting", "x86", "Exploit Development"]
date: "2021-07-27"
type: "post"
weight: 400
keywords: "hacking reversing reverse engineering"
---

> *"If you know the enemy and know yourself, you need not fear the result of a hundred battles."*
> 
>   --  Sun Tzu, The Art of War 

## Overview

Bit dramatic hey, and im not sure knowing yourself here will help much either but the point is:

> you have to understand the intricacies of how something works in order to attack it most effectively.

Enter reverse engineering. Reverse engineering, or 'reversing', is the process of taking something whose inner workings are not immediately clear or incredibly complex and making sense of them. Thus we see that reversing is not just a skill for security engineers but for all engineers, programmers and problem solvers. 

In this post we'll take a look at reverse engineering in the context of ELF 32 bit binaries and the accompanying x86 instruction set. We will see how to use pattern recognition to our advantage, harness the power of disassembler and untangle assembler logic.

## Tooling

In the bellow assembler code you will notice some adornments to register names and other data. This is produced by the disassembler [binaryninja](https://binary.ninja/), which I use for reversing. It has a 25 minute demo option which is enough time for analyzing miniature programs like many of the ones we will explore. However, if you need more time, ghidra, [cutter](https://cutter.re/), and radare are really good alternatives.

*Note: The graph view that these tools provide are of particular importance to reversing.*

## Basic Structures

In this segment we will look at reversing stripped back programs which show case one particular type of `C` *syntax*. In doing so we also highlight another powerful reversing technique, which I like to think of as being akin to 'chosen plaintext' attacks, creating and compiling snippets of `C` code to observe their assembly equivalents.


### `_start`

All ELF binaries contain the `_start` function and this is where execution begins, however, it is almost never relevant to understanding what the program does from an exploitation perspective but is worth mentioning. It has the following `x86` signature.

```nasm
_start:
endbr32 
xor     ebp, ebp  {0x0}
pop     esi {__return_addr}
mov     ecx, esp {arg_4}
and     esp, 0xfffffff0
push    eax {var_4}
push    esp {var_4} {var_8}
push    edx {var_c}
call    sub_10a6
add     ebx, 0x2f58
lea     eax, [ebx-0x2d9c]  {__libc_csu_fini}
push    eax {var_10}  {__libc_csu_fini}
lea     eax, [ebx-0x2e0c]  {__libc_csu_init}
push    eax {var_14}  {__libc_csu_init}
push    ecx {arg_4} {var_18}
push    esi {var_1c}
push    dword [ebx+0x1c] {var_20}  {main}  {data_3ff8}
call    __libc_start_main
{ Does not return }
```


### `main.c`

Main is the real starting point of interest for all C programs, it is from here that all of the programs logic branches out. A typical `C` code representation looks like the following.

```C
int 
main(int argc, char const *argv[])
{
	return 0;
}
```

Lets examine the `x86` signature.


```nasm
main:
endbr32 
push    ebp {__saved_ebp}
mov     ebp, esp {__saved_ebp}
call    __x86.get_pc_thunk.ax
add     eax, 0x2e23  {_GLOBAL_OFFSET_TABLE_}
mov     eax, 0x0
pop     ebp {__saved_ebp}
retn     {__return_addr}
```

Firstly we see the label for the function `main:` which is true of all functions. Then we see the odd instruction `endbr32` this is another one of those instructions that is not too important to know, but essentially it is just a safety instruction that is *"used to mark valid jump target addresses of indirect calls and jumps in the program"* (intel). 

Now like all functions the stack frame is setup. We begin by pushing the saved base pointer `ebp` from the callee function (`_start` in this case) onto the stack. The new frame is then setup by moving the stack pointer for the frame `esp` into the base pointer `ebp`. What this means in that now the current place we are up to, A.K.A the entry to the function, is now the base of our frame (stack). From here we would ordinarily setup space for local function variables and the like but since our 'main' function simply returns `0` we don't allocate any space in our frame. The next instruction `call __x86.get_pc_thunk.ax` is another one of those operations which we see frequently but is not of great importance but we will address it anyway. In essence the call simply retrieves the next instructions address from `eax`. *I'm not entirely sure why it exists at all or why it is needed*. Next we see the assembler loads the address of the `GOT` or 'Global offset table' into eax and finally we see the return value for the function `0` being loaded into the standard address for function returns `eax`.

We now proceed to the functions epilog where we clean up the created stack frame before returning. Again because we do not initialize any local variables in `main` we don't need to restore any allocated space so we simply pop the saved `ebp` off the stack. Remember pop takes the last 4 bytes pushed onto the stack and saves them into the specified register, thus, since the last thing pushed was the saved `ebp` value we know that this will be the value pop'd. Finally we call `retn` which is 'return near' which simply returns us to the callee function.

### `types.c`

Now lets take a look at how different types are represented in assembly. We will use the following stripped back `C` program to do so.

```C
int 
main(int argc, char const *argv[])
{
	char a;
	int b;
	short c;
	long d;
	unsigned int e;
	float f;
	double g;


	return 0;
}
```


### `add.c`


### `sub.c`


### `multiply.c`


### `division.c`


```C
int 
main(int argc, char const *argv[])
{
	int res;

	int a = 235000;
	int b = 431231;

	res = a / b;

	return 0;
}
```

### `modulo.c`


### `conditionals.c`


### `loops.c`


```C
int 
main(int argc, char const *argv[])
{
	/* for */
	for (int x = 0; x < 10; x++){
		// spin
	}

	return 0;
}
```


```C
int 
main(int argc, char const *argv[])
{
	/* while */
	while (1) 
	{
		//spin
	}

	return 0;
}
```

### `arrays.c` 


### `functions.c`


### `bitshifts.c`

## Scoping and Intermediate Structures

### `structs.c`


### `unions.c`


### `globals.c`


### `arguments.c`


### `recursion.c`



### `switches.c`


### `casting.c`


## I/O


### `files.c`


### `syscalls.c`



## Data Structures & Basic Algorithms

### `linkedlist.c`


### `queue.c`


### `stack.c`


### `hashtable.c`


### `tees.c`