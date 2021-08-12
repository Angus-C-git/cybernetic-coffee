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


## Basic Structures

In this segment we will look at reversing stripped back programs which show case one particular type of `C` *syntax*. In doing so we also highlight another powerful reversing technique, which I like to think of as being akin to 'chosen plaintext' attacks, creating and compiling snippets of `C` code to observe their assembly equivalents.


### `main.c`

```C
int 
main(int argc, char const *argv[])
{
	return 0;
}
```

### `types.c`


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