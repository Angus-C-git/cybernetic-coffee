---
title: "ROP Emporium Revisited"
categories: ["Hacking", "Binary Exploitation"]
tags: ["hacking", "pentesting", "pwntools", "Exploit Development"]
date: "2021-07-27"
type: "post"
weight: 400
keywords: "hacking rop pwntools"
---

## Overview



> ROP highlights a classical strategy across all facets of security exploitation, living off the land.



## ret2win #2

`ret2win` is the first challenge among the rop emporium suite and plays out like a classical [buffer overflow](../basic-stack-based-overflows). The only real takeaway from this challenge is to note the state of the memory protections enabled for the binary.


```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

We see that the `NX` bit is **enabled** this is true of almost all ROP challenges since we wish to prevent execution off the stack with shellcode. We note however that we can still control the return pointer and thus redirect code execution. Our goal is to call the `ret2win` function, but why can we even call this function?

If you understand the notion off living off the land you will recognize the key utility of ROP and why it can be used to circumvent no execute (`NX`) memory protections. The instructions we execute *already exist within the program* after compilation.

In this case that code is the win function `ret2win` but there are many other instructions within the binary, some which are never even used by the program in its running lifetime ... 

Compilers are not perfect programs, and indeed `x86` as an instruction set has its oddities, they leave behind garbage instructions as well as carrying out other weird behavior. 

> These leftover instructions, often called 'gadgets', can be of great use to us.

They are an example of a [weird machine](https://en.wikipedia.org/wiki/Weird_machine). We will explore their utility in detail as we continue but for now know they exist alongside the functions and other instructions that make up the program.

With this understanding, we proceed by fuzzing the offset to the return pointer with cyclic (yes even tho it tells us the bytes to overwrite). We can then hook `ret2win` from the symbols table and use `fit/flat` to pad the offset to our packed address.

The exploit for the 32 bit binary (this is the track we will follow) is as follows.


```python
from pwn import *
proc = process('./ret2win32')

## get da banner
log.info('Receiving banner ...')

payload = fit({
    cyclic_find('laaa'): p32(elf.symbols['ret2win'])
})

proc.sendafter('> ', payload)
# shellit
proc.interactive()
```

## split

//TODO 