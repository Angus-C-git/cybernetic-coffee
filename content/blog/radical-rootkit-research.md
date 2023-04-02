---
title: 'Radical Rootkit Research'
categories: ['Hacking', 'Rootkits', 'Post Exploitation', 'security research']
tags:
  [
    'Exploit Development',
    'hacking',
    'redteaming',
    'rootkits',
    'security research',
  ]
date: '2020-03-04'
type: 'post'
weight: 400
keywords: 'hacking rootkits'
---

This series of blog posts covers some research I did into rootkits with a focus on Linux kernel based rootkits via malicious drivers. Over the series I implement a rudimentary poc, source [here](https://github.com/Angus-C-git/VERTO)

> Note at the time of writing the rootkit I had previously never written C and undertook this project as a means to learn it. If you like that idea you should checkout [Creating a Rootkit to Learn C ](https://h0mbre.github.io/Learn-C-By-Creating-A-Rootkit/) which I only found after I finished this little project. Nothing here is properly reviewed take with a big granule of salt.

## Overview

What is a rootkit? What are the fundamental building blocks of a user mode rootkit? How are these rootkit components programmed? What do rootkits rely on to deploy and operate? What differences occur in rootkits across different platforms?

This week focuses on narrowing down conceptually how rootkits, and specifically user mode rootkits, work in detail. It begins with an overview of what a rootkit is as a piece of software and begins to analyse and breakdown what technologies and operating system components rootkits rely on to operate. Then based on this analysis we analyse how these components alter rootkits across other deployment platforms. Closing with an overview of the project's direction with a redefined scope.

## What is a rootkit?

As with many names in computing, and perhaps more specifically security, the splitting of the word into its ‘roots’, if you will, is a useful tool to more easily understand and identify what a particular term means. In the case of rootkit its subdivision into ‘root’ and ‘kit’ is a telling separation. The term ‘root’ echos (pun_count += 1) back to the default, and standard, name given to the ‘super user’ or fully privileged account on Unix based operating systems, Linux, and it's distros as well asMac Os. Thus the term ‘root’ is usually thrown around to mean having full control over a system, “Duuude I just rooted that machine in less than 10 minutes”. The phrase ‘kit’ in the word is less defined (in my lowly opinion) with a happy middle ground between the wikipedia definition “...the software components that implement the tool” and my own perception of it as something which facilitates, like a first aid kit -> it facilitates first aid’. Thus the combination of these two sub terms leads us to the definition of a rootkit being a piece of software or a tool that facilitates root access or in other words allows a remote attacker to maintain control of the system on which it is deployed.

## ‘User Mode’ rootkits: Deployment & Operation

A user mode rootkit is a rootkit which is run in the user level of access, rather than at kernel or lower level modes. A model exists, the ring model, which denotes the ‘security’ level at which a piece of software runs. User mode rootkits exist in ‘Ring 3’ along with other applications that execute as a user.

![CPU ring scheme](https://lh5.googleusercontent.com/GiNmpBC_lAlOUpgP9kErDW4QYbC7y1Z1oJTg0mR9S9ZchqyCZu_uUWd4O7g5n-3P3UcLzv95ZT-GjpsKs7vD3LgA9haq40lhz-Bf7a_EmkuIwo5M_x3CUtjGCDMoWEW4R1dsW72X)

> Security Rings scheme

The critical concept to grasp here is that a user mode rootkit can be just as powerful as a kernel mode rootkit. What makes this possible is the way in which information is transferred between these rings, processes executing in ring 3 still need to execute code from the kernel level (for operational purposes), to send calls to lower levels the process which sends the call undergoes a ‘privilege check’ at each of the ring levels, if it passes the CUP/Os will execute the call/instructions. This system relies on trusting that the parameters sent from ring 3 are not malicious and that the process from which it was sent has not been compromised. It is this mechanism that user mode rootkits depend on to operate with higher privileges and execute arbitrary code at the kernel level. A user mode rootkit does this (~typically) through an operation called hooking. Hooking centers around intercepting, and then modifying or replacing, function calls, messages or events passed by an applications software components. User mode rootkits will utilise hooking to disguise their existence and to execute arbitrary code at higher privilege levels.

~Hooking will be explored at length in the context of user mode rootkits later on in the project when that part of the rootkit is being developed.

## User mode rootkits across platforms

A user mode rootkit deployed on Windows will have a significantly different operating life cycle than one deployed on Linux. This is largely because of the way running processes work on linux and the difference in the way linux and windows include/call/access library code, that is code external to the main program. This difference is of critical importance to user mode rootkits as it is often what allows the rootkit to execute arbitrary code at root level. Where Windows uses dynamic-link libraries (DLLs) to implement shared libraries, Linux uses ‘Shared Object’ (SO). Therefore where a Windows user mode rootkit may rely on DLL injection a linux deployment may rely on shared object injection. These two methods are fundamentally different and thus the rootkit cannot be cross platform if it utilises shared library injection.

## Project Direction

The development of this project will likely have two very clear phases; a large research phase followed by a parallel development phase. The research phase is a necessary evil to avoid diving headfirst into unknown territory, wasting a lot of time (of which there is little) and having a clunky end product, without direction or vision of the result. The parallel development phase will, hopefully, be largely devoted to building a component of the rootkit with research being of finer technical detail.

The next stage of the pre-research phase will contrast user mode rootkits and kernel mode rootkits, decide on one of them and select a target operating system.
