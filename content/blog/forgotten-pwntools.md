---
title: "Forgotten pwntools"
categories: ["Hacking", "Binary Exploitation"]
tags: ["hacking", "pentesting", "Exploit Development"]
date: "2021-08-24"
type: "post"
weight: 400
keywords: "hacking pwntools"
toc: "true"
---


You'd think after searching for `/bin/sh` in libc that many times in `pwntools` that I'd remember the syntax. But actually my brain is too busy remembering when the milk in the fridge expires. Here's a collection of my favorite forgotten syntactic gems for `pwntools`.


## General

### `flat`

```python
payload = flat({
    # pad with garbage to this offset
    cyclic_find('amia'): rop.chain()
})
```

**custom filler**

```python
alphabet = 'bcdefhijklmnopqrstuvwyz'     # cleansed alphabet

payload = fit({
    cyclic_find('nbbb', alphabet=bet): rop.chain()
}, filler=alphabet)
```

### `logging`

```python
log.info(f"Data section @ {data_section}")
log.success(f"Leaked libc system @ {libc_system_addr}")
```

### `sections`

```python
data_section = elf.symbols.data_start
```

### `rebase`

```python
libc.address = leaked_setbuf_libc - libc.symbols['setbuf']
elf.address = leaked_menu_address - elf.symbols['menu']

# now we have defeated PIE/ASLR globally
```


## ROP

### `raw`


```python
rop = ROP(binary)

rop.raw([
    pop_eax_edx,
    'flag',
    0x0
])

```

### `libc.search`

```python
libc = ELF('<some-libc>.so')

# Its an iterator guys
next(libc.search(b'/bin/sh'))
```

### `call`

```python
rop = ROP('<some-libc>.so')

rop.call(libc.symbols['system'], [next(libc.search(b'/bin/sh'))])
```


### `function`

```python
rop = ROP(binary)

# call function in symbols table with args
rop.some_function(arg1, arg2)
```
