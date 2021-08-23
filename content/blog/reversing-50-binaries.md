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

> *"If you know the enemy and know yourself, you need not fear the ~~result~~ disassembly of ~~a hundred battles~~ fifty binaries."*
> 
>   --  Sun Tzu, The Art of ~~War~~ Exploitation

## Overview

~~So you want to hack a program? Go to nsogroup.com~~ ...

Reverse engineering, or 'reversing', is the process of taking something whose inner workings are not immediately clear or incredibly complex and making sense of them. Thus we see that reversing is not just a skill for security engineers but for all engineers, programmers and problem solvers. 


> *I'll never stop to be amazed by the amount of efforts people put into not understanding things*
>
> -- Mark Dowd

In this post we'll take a look at reverse engineering in the context of ELF 32 bit binaries and the accompanying x86 instruction set. We will see how to use pattern recognition to our advantage, harness the power of dissembler's and untangle assembler logic.

## Tooling

In the bellow assembler code you will notice some adornments to register names and other data. This is produced by the disassembler [binaryninja](https://binary.ninja/), which I use for reversing. It has a 25 minute demo option which is enough time for analyzing miniature programs like many of the ones we will explore. However, if you need more time, ghidra, [cutter](https://cutter.re/), and radare are really good alternatives.

*Note: The graph view that these tools provide are of particular importance to reversing.*

## Basic Structures and Operations

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

Once again looking at the `x86` disassembly in binja we obtain the following block.


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

Now for disguised addition, lets check out multiplication. 

```C
int
multiply ()
{
	int a = 7;
	int b = 2;
	int c = 3;

	return a * b * c;
}

void main() {multiply();}
```

This is the compiled codes disassembly.

```nasm
multiply:
endbr32 
push    ebp {__saved_ebp}
mov     ebp, esp {__saved_ebp}
sub     esp, 0x10
call    __x86.get_pc_thunk.ax
add     eax, 0x2e20  {_GLOBAL_OFFSET_TABLE_}
mov     dword [ebp-0xc {var_10}], 0x7
mov     dword [ebp-0x8 {var_c}], 0x2
mov     dword [ebp-0x4 {var_8}], 0x3
mov     eax, dword [ebp-0xc {var_10}]
imul    eax, dword [ebp-0x8]
imul    eax, dword [ebp-0x4]  {0x2a}
leave    {__saved_ebp}
retn     {__return_addr}
```

Now that we know about register conventions we can already put together some assumptions about the program with just a quick passover the disassembly. We know that the result is being computed and returned directly via the `eax` register and that there are 3 variables involved. Additionally all the variables are of size `dword` so we can also attribute typing information to the variables. Simple conversion of the hexadecimal constants we have the following rough scaffold.

```C
int
multiply ()
{
	int var_10 = 7;
	int var_c = 2;
	int var_8 = 3;

	return /*todo*/;
}
```

Now lets address the opcode in the room, `imul` or 'signed multiply'. According to a [website](https://www.felixcloutier.com/x86/imul) that hasn't discovered CSS which means it can be trusted completely:

> *"imul Performs a signed multiplication of two operands. This instruction has three forms, depending on the number of operands."*

Thus `imul` behaves differently depending on the number of operands, the cases are (approximately) as follows:

**One operand**

```nasm
imul edi
imul dword [ebp-0x42]
```

The value in the source operand, which can be either a memory location or a general purpose register, is multiplied with the value in the `eax` register (or its 8 bit equivalent `al` depending on the size of the value) and the result stored/returned in the `edx` or `eax` registers.

**Two operands**

```nasm
imul eax, edi
imul eax, 0x42
imul eax, dword [ebp-0x42]
```

The value in the destination operand, which must be a general purpose register, is multiplied with the source operand, which may be either a general purpose register, constant value or a memory location, and the result stored/returned in the destination register/operand.


**Three operands**

```nasm
imul eax, edi, 0x42
imul eax, dword [ebp-0x42], 0x42
```

The second operand, which can either be a general purpose register or a memory location, is multiplied with the third operand, which must be a constant value, and the result is stored in the first operand, which must be a general purpose register.


**Our Case**

Here we deal with `imul's` of the second format with two operands the second being a location in memory. Thus we can follow the logic

1. `mov     eax, dword [ebp-0xc {var_10}]` the value in `var_10` is stored into the `eax` register
	
	i. `eax = 7`

2. `imul    eax, dword [ebp-0x8]` the value in eax is multiplied with the value in `var_c`

	ii. `eax = 7 * 2 = 14`

3. `imul    eax, dword [ebp-0x4]` the value in eax is multiplied with the value in `var_8`

	iii. `eax = 14 * 3 = 42`

Thus we obtain the final reconstructed `C` snippet.


```C
int
multiply ()
{
	int var_10 = 7;
	int var_c = 2;
	int var_8 = 3;

	return var_10 * var_c * var_8;
}
```

### `division.c`

Now lets take a look at a slightly different one, division.

```C
int 
divide()
{
	int res;

	int a = 235000;
	int b = 431231;

	res = a / b;

	return res;
}

void main() {divide();}
```


Which has the following signature in `x86`.


```nasm
divide:
endbr32 
push    ebp {__saved_ebp}
mov     ebp, esp {__saved_ebp}
sub     esp, 0x10
call    __x86.get_pc_thunk.ax
add     eax, 0x2e20  {_GLOBAL_OFFSET_TABLE_}
mov     dword [ebp-0xc {var_10}], 0xe01d0c0
mov     dword [ebp-0x8 {var_c}], 0x19b41018
mov     eax, dword [ebp-0xc {var_10}]
cdq       {0xe01d0c0}
idiv    dword [ebp-0x8 {var_c}]
mov     dword [ebp-0x4 {var_8}], eax
mov     eax, dword [ebp-0x4 {var_8}]
leave    {__saved_ebp}
retn     {__return_addr}
```

We see the typical stack frame setup stuff going on ra ra ra, ignore all that and go straight for our freebies, the variable setups.

```C
int var_10 = 235000000;
int var_c = 431231000;
```

Then we encounter this series of events.

```nasm
mov     eax, dword [ebp-0xc {var_10}]
cdq       {0xe01d0c0}
idiv    dword [ebp-0x8 {var_c}]
mov     dword [ebp-0x4 {var_8}], eax
```

We see our value in `var_10` being shoveled into the `eax` register which is a fair indicator that we are about to perform some operation or a function call. On the next line we have the `cdq` instruction which converts the value stored in `eax` to either a double word or a quadword depending on the values original 'type'. Thus in this case we convert a `dword` to a `qword` to facilitate the next instruction. The `idiv` instruction handles signed division of ([smaller](#moduloc)) numbers in `x86`. It takes in one operand only as a divisor and divides the value stored in the `eax` register by that operands value storing the result back into `eax` (as all functions do conventionally). Finally we see `eax` saved into an intermediate variable `var_8`.

```C
int div_result;

int var_10 = 235000000;
int var_c = 431231000;

// take note of order, eax value first
div_result = var_10 / var_c;
```

In the last block we have,

```nasm
mov     eax, dword [ebp-0x4 {var_8}]
leave    {__saved_ebp}
retn     {__return_addr}
```

which we know means the result in `var_8` is being returned from the function. Thus we have the final `C` snippet.

```C
int
divide()
{
	int div_result;
	int var_10 = 235000000;
	int var_c = 431231000;

	// take note of order, eax value first
	div_result = var_10 / var_c;

	return div_result;
}

```


### `modulo.c`

I find modulo to be one of the more interesting arithmetic operations to reverse since it highlights 'weird' compiler optimizations.

```C
int 
modulo ()
{
	int res;
	int a = 6;
	/* modulo*/

	res = a % 3;
	return res;
}

void main() {modulo();}
```

Bellow is the disassembly.


```nasm
modulo:
endbr32 
push    ebp {__saved_ebp}
mov     ebp, esp {__saved_ebp}
sub     esp, 0x10
call    __x86.get_pc_thunk.ax
add     eax, 0x2e20  {_GLOBAL_OFFSET_TABLE_}
mov     dword [ebp-0x8 {var_c}], 0x6
mov     ecx, dword [ebp-0x8 {var_c}]
mov     edx, 0x55555556
mov     eax, ecx
imul    edx
mov     eax, ecx
sar     eax, 0x1f
sub     edx, eax
mov     eax, edx
add     eax, eax
add     eax, edx
sub     ecx, eax
mov     edx, ecx
mov     dword [ebp-0x4 {var_8}], edx
mov     eax, dword [ebp-0x4 {var_8}]
leave    {__saved_ebp}
retn     {__return_addr}
```


I'll skip the usual variable setup here since its becoming a little beyond repetitive and get straight to the 'meat' of the function.

```nasm
mov     ecx, dword [ebp-0x8 {var_c}]
mov     edx, 0x55555556
mov     eax, ecx
imul    edx
mov     eax, ecx
sar     eax, 0x1f
sub     edx, eax
mov     eax, edx
add     eax, eax
add     eax, edx
sub     ecx, eax
mov     edx, ecx
```

What in the fuck is happening here? Personally the most confusing elements when first presented with this is

1. Where and why do we have the big fuck off number being moved into `edx`?
2. Why do we have a `imul` instruction when we are dealing with modulo (ofc we don't know this normally)?

My strategy when I first encountered it was to punch "big fuck off constant in disassembly" into a search bar. Which unsurprisingly did not yield particularly helpful results, eventually however I uncovered a [stack overflow](https://stackoverflow.com/questions/41183935/why-does-gcc-use-multiplication-by-a-strange-number-in-implementing-integer-divi) post which is only 4 years old that lead to a bunch of helpful resources including [this](https://ridiculousfish.com/blog/posts/labor-of-division-episode-i.html) excellent blog. 

Basically, in short, the compiler uses this 'large fuck off' constant as a kind of magic number in order to optimise the modulo operation and indeed more generally division operations, which of course are required for modulo calculations, where the divisor is constant. This last distinction **where the divisor is constant** is important. We saw earlier in our [division](#divisionc) that no such large unexplained constant appears. This is because we divide two variables `a / b` and thus the compiler does not make the optimization. 

If we instead had `a / 42` we would end up with a disassembly like,

```nasm
mov     edx, 0x30c30c31
mov     eax, ecx
imul    edx
mov     eax, edx
sar     eax, 0x3
sar     ecx, 0x1f
mov     edx, ecx
sub     eax, edx
```

where the magic number for perform divisions with multiply and shifting is `0x30c30c31`. 

Thus we have a similar output for our modulo operation where our magic number is `0x55555556`. But how does the compiler select this magic number? The aforementioned [blog](https://ridiculousfish.com/blog/posts/labor-of-division-episode-i.html) does a much better of explaining this so I would recommend reading that. I will, however, attempt a explanation of how we convert such logic back into `C`.

The first step is to identify two key pieces of information:

1. The shift constant
2. The magic number

To obtain the first we must first know what `x86` shift instructions look like. There are four main ones namely `sar`, `sal`, `shl` and `shr`. To read more about them have a look [here](https://www.felixcloutier.com/x86/sal:sar:shl:shr). For now it is enough to know of their existence and symbols. In our modulo disassembly we only have one such instruction.

```nasm
sar     eax, 0x1f
```

A 'shift arithmetic right' with operands `eax` and decimal constant `31`. Thus our shift constant (1) is `31`. The next step is equally as straight forward simply take the large hex number and convert it to its decimal form (or not up to you) `0x55555556 = 1431655766`.

We now do the following:

1. Take the shift constant and add `1` to it
2. Take the adjusted shift constant and calculate `2` to the power of that number
3. Take that value and divide by `x` setting the RHS to the value of the magic number
4. Solve for `x`

Thus for our case we would perform the following arithmetic:

```
shift_constant = 31 + 1
exp_shift = 2**shift_constant

exp_shift / x = 1431655766
x = exp_shift / 1431655766
x = 2**32 / 1431655766
  = 2.99999 ...
  = 3
```

We now have to note that this method of 'fast' division / mod is not perfectly accurate it comes with an associated degree of error. This is why we end up with a modulo constant `2.9999` repeater which we must then round to the nearest whole number `3` to obtain the original constant used for the modulo operation. We can now simplify this whole operation into a simple python function like the bellow.


```python
def resolve_constant(magic, shift):
	return round(2 ** (shift + 1) / magic)
```

Putting this all together we can now build out our recovered `C` snippet.

```C
int
modulo()
{
	int mod_result;
	int var_c = 6;

	mod_result = var_c % 3;
	return mod_result;
}
```

### `conditionals.c`

Now we turn to what makes programs 

```C
int
conditional()
{
	int a = 9;
	int b = 10;

	if (a < b)
		return 1;
	
	return 0;
}


int main() {conditional();}
```

{{< image ref="images/blog/50_bins/conditionals.png" >}}


### `for.c`


```C
void
for_loop()
{
	for (int x = 0; x < 10; x++)
	{
		// spin
	}
}

void main() {for_loop();}
```


{{< image ref="images/blog/50_bins/for.png" >}}


### `while.c`

```C
void
while_loop()
{
	while (1) 
	{
		//spin
	}
}

void main() {while_loop();}

```


{{< image ref="images/blog/50_bins/while.png" >}}


### `arrays.c` 

```C

```


```nasm

```

### `functions.c`

```C

```

```nasm

```

### `bitshifts.c`

```C

```


```nasm

```

## Scoping and Intermediate Structures


### `arguments.c`

```C

```


```nasm

```


### `structs.c`

Structs are a very important structure forming the basis for many data structures in `C`. Lets explore a simple one.


```C
struct Tome {
	char category;
	int volume;
	char *title;
};


struct Tome
_struct()
{
	struct Tome tome;

	tome.category = 'A';
	tome.volume = 42;
	tome.title = "Computers are Evil";

	return tome;
}

void main(){_struct();}
```

The accompanying disassembly. 

```nasm
_struct:
endbr32 
push    ebp {__saved_ebp}
mov     ebp, esp {__saved_ebp}
sub     esp, 0x10
call    __x86.get_pc_thunk.ax
add     eax, 0x2dfc
mov     byte [ebp-0xc {var_10}], 0x41
mov     dword [ebp-0x8 {var_c}], 0x2a
lea     eax, [eax-0x1fd0]  {data_2008, "Computers are Evil"}
mov     dword [ebp-0x4 {var_8}], eax  {data_2008, "Computers are Evil"}
mov     eax, dword [ebp+0x8 {arg1}]
mov     edx, dword [ebp-0xc]  {0x41}
mov     dword [eax], edx  {0x41}
mov     edx, dword [ebp-0x8 {var_c}]  {0x2a}
mov     dword [eax+0x4], edx  {0x2a}
mov     edx, dword [ebp-0x4 {var_8}]  {data_2008, "Computers are Evil"}
mov     dword [eax+0x8], edx  {data_2008, "Computers are Evil"}
mov     eax, dword [ebp+0x8 {arg1}]
leave    {__saved_ebp}
retn    0x4 {__return_addr}
```

Naively we may proceed by allocating variables according to their size ('type') and obtain a `C` snippet similar to the following. 


```C
char var_10 = 'A';
int var_c = 42;
char *var_8 = "Computers are Evil";
```

But then we become confused, whats with all these extra `mov` operations? The First hint at a struct or at the very least a global variable is the appearance of this line.

```nasm
mov     eax, dword [ebp+0x8 {arg1}]
```

Which features the access to a memory location `[ebp+0x8 {arg1}]`. That is some data before our base pointer. Since we know that no arguments are supplied to the function this must represent a global variable. Regardless of what the global variable is we now know that its memory location is being stored in `eax` so we can proceed keeping this in mind.


```nasm
mov     edx, dword [ebp-0xc]  {0x41}
mov     dword [eax], edx  {0x41}
mov     edx, dword [ebp-0x8 {var_c}]  {0x2a}
mov     dword [eax+0x4], edx  {0x2a}
mov     edx, dword [ebp-0x4 {var_8}]  {data_2008, "Computers are Evil"}
mov     dword [eax+0x8], edx  {data_2008, "Computers are Evil"}
mov     eax, dword [ebp+0x8 {arg1}]
```

Over the next few instructions we will observe the behavior that is critical to the operation of a struct. On the first line our `A` byte is loaded into `edx` and on the proceeding line moved into the memory location of `eax`, the location of the identified 'global variable'. On the next two lines the 'spice' occurs.

```nasm
mov     edx, dword [ebp-0x8 {var_c}]  {0x2a}
mov     dword [eax+0x4], edx  {0x2a}
```

Firstly our integer `42` is stored into `edx` but then on the next line we store `42` into the memory location at `eax + 4` ??? 

Structs like many structures in `C`, namely arrays, are simply just 'contiguous' regions in memory (we ignore [alignment](https://www.geeksforgeeks.org/data-structure-alignment/) /padding for this conversation). *Thus the first member of the struct is also the 'address' of the struct in memory*. In our case the first struct member is the char byte `A` and hence to access the second member of the struct we can simply take the 'address' of the first member and add the size of the data type we are trying to store. Hence since we store an integer value as our second member we 'index' `4` bytes further from the start of the structs base in memory, leading to the above operation.

This logic follows for the next block.

```nasm
mov     edx, dword [ebp-0x4 {var_8}]  {data_2008, "Computers are Evil"}
mov     dword [eax+0x8], edx  {data_2008, "Computers are Evil"}
```

Where we store the `char` pointer another `4` bytes further into the struct as the last member. Finally we have the lines.

```nasm
mov     eax, dword [ebp+0x8 {arg1}]
leave    {__saved_ebp}
retn    0x4 {__return_addr}
```

Where we see the base of the struct (the structs address in memory) being returned from the function. This gives us all the information we need to muddle a `C` snippet together which describes the program.

```C
// declare global struct
struct Structure {
	char member_1;
	int member_2;
	char *member_3;
}

// must declare the type we return in C
struct Structure
_struct()
{
	// need to create a instance of the struct
	struct Structure structure;

	structure.member_1 = 'A';
	structure.member_2 = 42;
	structure.member_3 = "Computers are Evil";
	
	return structure;
}
```


### `unions.c`

```C

```


```nasm

```

### `globals.c`

```C

```


```nasm

```



### `recursion.c`

```C

```


```nasm

```

### `switches.c`


Switches are another classical decision making structure which see a lot of use in large programs and operating systems. When disassembled they generally resemble a set of nested `if/else` blocks. Lets look at this mock error handler as an example.

```C
#include <stdio.h>

void
_switch(int errno)
{
	switch (errno)
	{
		case 1:
			printf("One got us in the end\n");
			break;
		case 2:
			printf("Twosin't meant 2 be\n");
			break;
		case 3:
			printf("Third time wasn't the charm\n");
			break;
		default:
			printf("The front fell off\n");
			break;
	}
}

void main() {_switch(4);}
```

{{< image ref="images/blog/50_bins/switch.png" >}}


Its probably a good idea to view the image in another tab since its microscopic. Now at this point we might guess we are dealing with a switch, or at least after looking at this, however it is also perfectly possible to represent this as a series of `if/else` blocks. So lets start by doing that.

We begin by modeling out all the simple stuff and the rough scaffold. We also note that the first variable we see used `arg1` comes from `[ebp+0x8]` so we know that it is an argument supplied to the function.

```C
#include <stdio.h>

void
_switch(int arg1)
{
	if (arg1 == 3)
	{
		puts("Third time wasn't the charm");
	}

	else if (arg1 < 3)
	{
		if (arg1 == 1) {
			puts("One got us in the end");
		}

		else if (arg1 == 2) {
			puts("Twosin't meant 2 be");
		}

		else {
			puts("The front fell off");
		}
	}

	else {
		puts("The front fell off");
	}

	// no return
}
```

Now this is a disgusting mess of nested conditions but more importantly we see a couple of key things happening that hit towards the original source switch. Firstly we see that all the conditional `if/else` blocks check against the same variable `arg1`. Secondly we see repeated blocks. This could of course be dealt with by checking multiple conditions in the if statements but the structure of this particular program lends itself to simplification with a switch. *Another important aspect that I should mention also is that the `arg1` variable is of a type which is compatible with the switch.*

Thus we can rewrite the above logic to utilise a switch, we can also reorder the cases because we are human beings and not computers and prefer to look at things in a human logical sequence where `1` comes before `3`.

```C
void
_switch(int arg1)
{
	switch(arg1)
	{
		case 1:
			puts("One got us in the end");
			break;
		case 2:
			puts("Twosin't meant 2 be");
			break;
		case 3:
			puts("Third time wasn't the charm");
			break;
		default:
			puts("The front fell off");
			break;
	}
}
```



### `casting.c`

```C

```


```nasm

```

## I/O


### `files.c`

```C

```


```nasm

```

### `cli.c`

Getting command line arguments is another typical I/O operation. 

```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int main(int argc, char const *argv[])
{
	/* code */

	if (argc != 3) {
		printf("Usage: %s <file> <mode>\n", argv[0]);
		exit(0);
	}

	FILE *fp;

	if (atoi(argv[2]))
		fp = fopen(argv[1], "w");
		
	else 
		fp = fopen(argv[1], "r");

	if (!fp) {
		printf("Could not open file\n");
		exit(1);
	}

	fclose(fp);
	return 0;
}
```


```nasm

```

### `sockets.c`

```C

```


```nasm

```


## Data Structures & Basic Algorithms

### `linkedlist.c`

```C

```


```nasm

```

### `queue.c`

```C

```


```nasm

```

### `stack.c`

```C

```


```nasm

```

### `hashtable.c`

```C

```


```nasm

```

### `trees.c`

```C

```


```nasm

```

## 'Complete' Programs

Lets put our new skills to the test and reverse some larger programs which combine a lot of the elements we see above.

### `argmultiplexer`


{{< image ref="images/blog/argmultiplexer.png" >}}


### `quickmafs`


{{< image ref="images/blog/quickmafs.png" >}}


### `rv_bind`


{{< image ref="images/blog/rv_bind.png" >}}


### `bitcastle`


{{< image ref="images/blog/bitcastle.png" >}}