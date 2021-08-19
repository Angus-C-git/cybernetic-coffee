---
title: "Reversing 50 Binaries for Fun and Regret"
categories: ["Hacking", "Reversing", "Binary Exploitation"]
tags: ["reversing", "hacking", "pentesting", "x86", "Exploit Development"]
date: "2021-07-27"
type: "post"
weight: 400
keywords: "hacking reversing reverse engineering"
toc: "true"
---

> *"If you know the enemy and know yourself, you need not fear the ~~result~~ assembly of ~~a hundred battles~~ fifty binaries."*
> 
>   --  Sun Tzu, The Art of ~~War~~ Exploitation

## Overview

~~So you want to hack a program? Go to nsogroup.com~~ ...

Reverse engineering, or 'reversing', is the process of taking something whose inner workings are not immediately clear or incredibly complex and making sense of them. Thus we see that reversing is not just a skill for security engineers but for all engineers, programmers and problem solvers. 


> *I'll never stop to be amazed by the amount of efforts people put into not understanding things*
>
> -- Mark Dowd

In this post we'll take a look at reverse engineering in the context of ELF 32 bit binaries and the accompanying x86 instruction set. We will see how to use pattern recognition to our advantage, harness the power of disassemblers' and untangle assembler logic.

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

*Note: when we talk about types here we do so in the context of 32bit programs*

Now lets take a look at how different types are represented in assembly. We will use the following stripped back `C` program to do so.

```C
int 
main(int argc, char const *argv[])
{
	char a = 'a';
	short c = 40;
	int b = 400;
	long d = 4000000000;
	unsigned int e = 400000000;
	float f = 4000.55;
	double g = 4000.58583;


	return 0;
}
```

Once again looking at the `x86` assembly in binja we obtain the following block.


```nasm
main:
endbr32 
push    ebp {__saved_ebp}
mov     ebp, esp {__saved_ebp}
and     esp, 0xfffffff8
sub     esp, 0x20
call    __x86.get_pc_thunk.ax
add     eax, 0x2e1d  {_GLOBAL_OFFSET_TABLE_}
mov     byte [esp+0x5 {var_23}], 0x61
mov     word [esp+0x6 {var_22}], 0x28
mov     dword [esp+0x8 {var_20}], 0x190
mov     dword [esp+0xc {var_1c}], 0xee6b2800  {0xee6b2800}
mov     dword [esp+0x10 {var_18}], 0x17d78400
fld     dword [eax-0x1fd4]
fstp    dword [esp+0x14 {var_14}]
fld     qword [eax-0x1fcc]
fstp    qword [esp+0x18 {var_10}]
mov     eax, 0x0
leave    {__saved_ebp}
retn     {__return_addr}
```

Now that we know how the main function, and functions more broadly, are setup we cant start by instantly ignoring all of the logic to setup the frame and 'weird' calls we explored prior. Thus we end up with an abstracted signature like the following.

```nasm
mov     byte [esp+0x5 {var_23}], 0x61
mov     word [esp+0x6 {var_22}], 0x28
mov     dword [esp+0x8 {var_20}], 0x190
mov     dword [esp+0xc {var_1c}], 0xee6b2800  {0xee6b2800}
mov     dword [esp+0x10 {var_18}], 0x17d78400
fld     dword [eax-0x1fd4]
fstp    dword [esp+0x14 {var_14}]
fld     qword [eax-0x1fcc]
fstp    qword [esp+0x18 {var_10}]
```

So as we expect for our 7 type variables we see 7 variables being initialized here. The important things we care about here to reverse the logic are the `x86` types and the weird instructions we see.

Lets start by revisting the `x86` types.

+ `byte` - In a shocking twist this is a `8 bit (1 byte)` quantity
  + `0 - 255` unsigned range
+ `word` - A word is two bytes giving us a `16 bit (2 byte)` quantity
  + `0 - 65535` unsigned range
+ `dword` - A double word, you guessed it, a `32 bit (4 byte)` quantity
  + `0 - 4294967295` unsigned range
+ `qword` - A quad word, a `64 bit (8 byte)` quantity
  + `0 - 18446744073709551615` unsigned range


With this in mind we can start converting some of our easier types into their `C` equivalents. 

```nasm
mov     byte [esp+0x5 {var_23}], 0x61
```

This value must be a `char` and the hex value `0x61` falling within the ASCII character range is a dead giveaway that its the character `a`. So we now have the following `C` snippet

```C
int 
main(int argc, char const *argv[])
{
	char var_23 = 'a';
}
```

Next up we have another relatively straightforward one. 

```nasm
mov     word [esp+0x6 {var_22}], 0x28
```

For starters we know we are dealing with a word which is `16 bits` in size. If we look at some `C` types we can accumulate the following list. For a better list see [Basic Types Table](https://devsheets.cybernetic.coffee/programming-languages/basic-c-syntax/#basic-types).

+ `char` - `1 byte`
	+ `0 - 255` (unsigned)
	+ `-128 - 127` (signed)
+ `short` - `2 bytes`
	+ `0 - 65535` (unsigned)
	+ `-32,768 - 32,767` (signed)
+ `int` - `4 bytes`
	+ `0 - 4294967295` (unsigned)
	+  `-2,147,483,648 - 2,147,483,647` (signed)

Now comparing this to the `x86` equivalents we know that a word will range from `0 - 65535` which corresponds to a short. Next we see `0x28` is moved into the place the variable points in memory,
+ `[]` indicates a dereference  

if we convert this to decimal we get the value `40` and thus we obtain the next `C` snippet.

```C
int 
main(int argc, char const *argv[])
{
	char var_23 = 'a';
	short var_22 = 40;
}
```

We now proceed with the following snippet.

```nasm
mov     dword [esp+0x8 {var_20}], 0x190
```

At this stage we have the pattern sorted so we skip straight to matching the size and convert the hex to decimal `400` and produce the `C` snippet.

```C
int 
main(int argc, char const *argv[])
{
	char var_23 = 'a';
	short var_22 = 40;
	int var_20 = 400;
}
```

Now its time for,

```nasm
mov     dword [esp+0xc {var_1c}], 0xee6b2800  {0xee6b2800}
```

at this point you're like its a `int` mate, and you'd be correct, for 32 bit programs, and ofc systems, `longs` and `ints` are both the same size `4 bytes`. Hence we make the hex conversion and assume an integer. *This assumption does not matter since any vulnerabilities introduced by a `long` would be identical for an `int`*.

```C
int 
main(int argc, char const *argv[])
{
	char var_23 = 'a';
	short var_22 = 40;
	int var_20 = 400;
	int var_1c = 4000000000;
}
```

To save time with the following snippet we encounter a similar situation where the number of bytes used to represent the value is a `dword` which is the same size as the previously examined `int` and `long` values and thus all we can guarantee is that it will have at least the same size as an integer quantity in a 32 bit environment. 

```nasm
mov     dword [esp+0x10 {var_18}], 0x17d78400

```

```C
int 
main(int argc, char const *argv[])
{
	char var_23 = 'a';
	short var_22 = 40;
	int var_20 = 400;
	int var_1c = 4000000000;
	int var_18 = 400000000;
}
```

Now we start getting into the 'interesting' parts of the program, lets look at the next snippet.

```nasm
fld     dword [eax-0x1fd4]
fstp    dword [esp+0x14 {var_14}]
```

Here we encounter two new unfamiliar instructions.

+ `fld` - Load Floating Point Value
+ `fstp` - Store Floating Point Value


Both are irresponsible for interacting with the floating point register so we know we are dealing with some kind of floating point value. What is interesting however here is that we don't see any associated value being moved around we just get a dereference to `var_14`. This is because for whatever reason floating point values are stored in the `.rodata` section of the ELF. The information we can figure out here tho is the type of precision associated with the floating point value. In this case we see that the size of the data referenced at that memory location is a `dword`. That means the floating point value is represented by a `4 byte` value. Hence we can determine by looking at the spec that this is a floating point value with the precision of the `C` type `float`.

```C
int 
main(int argc, char const *argv[])
{
	char var_23 = 'a';
	short var_22 = 40;
	int var_20 = 400;
	int var_1c = 4000000000;
	int var_18 = 400000000;
	float var_14; // unknown value
}
```

Finally we see a very similar instruction sequence.

```nasm
fld     qword [eax-0x1fcc]
fstp    qword [esp+0x18 {var_10}]
```

With the only difference being the precision of the floating point value which we now see has increased to `8 bytes` in size. This corresponds to the `C` type of `double`. 

This completes our recovered `C` snippet leaving us with two unresolved values of known type. If we desired we could easily recover the values with further static analysis on the `.rodata` section or with dynamic analysis in GDB.

```C
{
	char var_23 = 'a';
	short var_22 = 40;
	int var_20 = 400;
	int var_1c = 4000000000;
	int var_18 = 400000000;
	float var_14; // unknown value
	double var_10; // unknown value
}
```

### `add.c`

Next up lets get into some basic arithmetic starting with every computers favorite, addition.

```C
int
add()
{
	int a = 40;
	int b = 2;
	return a + b;
}


void main() {add();}
```

Opening the compiled binary in binja we get the following disassembly for the `add` function.

```nasm
add:
endbr32 
push    ebp {__saved_ebp}
mov     ebp, esp {__saved_ebp}
sub     esp, 0x10
call    __x86.get_pc_thunk.ax
add     eax, 0x2e20  {_GLOBAL_OFFSET_TABLE_}
mov     dword [ebp-0x8 {var_c}], 0x28
mov     dword [ebp-0x4 {var_8}], 0x2
mov     edx, dword [ebp-0x8 {var_c}]
mov     eax, dword [ebp-0x4 {var_8}]
add     eax, edx  {0x2a}
leave    {__saved_ebp}
retn     {__return_addr}
```

As we will often do from here start by nuking the 'boilerplate' used to setup and collapse the stackframe.

```nasm
mov     dword [ebp-0x8 {var_c}], 0x28
mov     dword [ebp-0x4 {var_8}], 0x2
mov     edx, dword [ebp-0x8 {var_c}]
mov     eax, dword [ebp-0x4 {var_8}]
add     eax, edx  {0x2a}
leave    {__saved_ebp}
```

To begin with we see two variables being setup. Now that we can reverse types it's pretty easy to see that we assign two integers as follows.

```C
int var_c = 40;
int var_8 = 2;
```

Over the next few lines we see the variables being moved into general purpose registers `edx` and `eax` in preparation for the `add` instruction. The `add` instruction takes in two parameters a source register which will be updated with the value stored in the second register. Thus in this case the value in `eax` is added with the value in `edx` and the computed sum stored back into `eax`. We then see the leave instruction is executed and the function terminates.

It is at this point that we should recall the `x86` calling convention, wherein it is standard to return the results of function calls in the `eax` register. This should now make it obvious to us that the result of the addition operation is returned from the function directly rather than storing it in a result variable and then returning that. Thus we obtain the final recovered `C` snippet.

```C
int
add()
{
	int var_c = 40;
	int var_8 = 2;

	return var_8 + var_c; 
}
```


### `sub.c`

Now lets take a look at the inverse operation subtraction.

```C
int
sub()
{
	int a = 40;
	int b = 2;
	return a - b;
}


void main() {sub();}
```

As you might expect the disassembly is virtually identical to add so we wont spend much time here.

```nasm
sub:
endbr32 
push    ebp {__saved_ebp}
mov     ebp, esp {__saved_ebp}
sub     esp, 0x10
call    __x86.get_pc_thunk.ax
add     eax, 0x2e20  {_GLOBAL_OFFSET_TABLE_}
mov     dword [ebp-0x8 {var_c}], 0x28
mov     dword [ebp-0x4 {var_8}], 0x2
mov     eax, dword [ebp-0x8 {var_c}]
sub     eax, dword [ebp-0x4]  {0x26}
leave    {__saved_ebp}
retn     {__return_addr}

```

The only difference being that the `add` instruction is replaced with the `sub` instruction which works in the exact same fashion as `add` where the value in the first register parameter is reduced by the amount stored in the second register parameter and the result stored back into the first register. However, in this case the compiler just takes the value stored at the memory address of `var_8` as the second parameter rather than storing it in a general purpose register (like `edx`). Hence we have the following `C` snippet.

```C
int
sub()
{
	int var_c = 40;
	int var_8 = 2;

	// order is important
	return var_c - var_8; 
}
```


### `multiply.c`

```C

```

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

```C
int 
main(int argc, char const *argv[])
{
	int res;
	int a = 6;
	int b = 1;
	/* modulo*/

	res = a % b;
	return 0;
}
```

### `conditionals.c`


```C
int 
main(int argc, char const *argv[])
{
	
	int a = 9;
	int b = 10;

	if (a < b)
		return 1;
	
	return 0;
}
```

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

```C

```

### `functions.c`

```C

```

### `bitshifts.c`

```C

```


## Scoping and Intermediate Structures

### `structs.c`

```C

```

### `unions.c`

```C

```

### `globals.c`

```C

```

### `arguments.c`

```C

```

### `recursion.c`

```C

```

### `switches.c`

```C

```

### `casting.c`

```C

```

## I/O


### `files.c`

```C

```

### `sockets.c`

```C

```


## Data Structures & Basic Algorithms

### `linkedlist.c`

```C

```

### `queue.c`

```C

```

### `stack.c`

```C

```

### `hashtable.c`

```C

```

### `tees.c`

```C

```


## 'Complete' Programs

Lets put our new skills to the test and reverse some larger programs which combine a lot of the elements we see above.

### `argmultiplexer`


{{< image ref="images/blog/argmultiplexer.jpeg" >}}


### `calculator`


{{< image ref="images/blog/calculator.jpeg" >}}


### `rv_bind`


{{< image ref="images/blog/rv_bind.jpeg" >}}


### `bitprotect`


{{< image ref="images/blog/bitprotect.jpeg" >}}