---
title: 'Kernel Mode Rootkits'
categories: ['Hacking', 'Rootkits', 'Post Exploitation', 'security research']
tags:
  [
    'Exploit Development',
    'hacking',
    'redteaming',
    'rootkits',
    'security research',
  ]
date: '2020-03-14'
type: 'post'
weight: 400
keywords: 'hacking rootkits'
---

What is a kernel mode rootkit? How is a kernel mode rootkit developed?

This week looks at the second alternative 'type' of rootkit that could be constructed over the course of the project. This post also provides reasoning for which combination of decision points have been chosen and details a development plan going forward.

## Kernel Mode Rootkits

Unlike ‘user mode’ rootkits, which were discussed last week, kernel mode rootkits execute directly at kernel level privilege. This means they operate at the highest level of privilege on the system, in regard to the previously introduced ‘Security Ring’ model they execute within ring-0:

![CPU ring scheme](https://lh5.googleusercontent.com/GiNmpBC_lAlOUpgP9kErDW4QYbC7y1Z1oJTg0mR9S9ZchqyCZu_uUWd4O7g5n-3P3UcLzv95ZT-GjpsKs7vD3LgA9haq40lhz-Bf7a_EmkuIwo5M_x3CUtjGCDMoWEW4R1dsW72X)

The ‘advantage’ of deploying a rootkit in this mode is that it is inherently trusted by the operating system, as it is effectively part of the operating system itself. Software that runs within the ring-0 architecture is capable of both ‘direct’ communication with the systems hardware and applications and networking layers running in higher rings. It is therefore easier to maintain persistence on the system and hide the rootkit more effectively as it is already out of the scope of the majority of antivirus and system scans.

## Kernel Mode Rootkit Development

As kernel mode rootkits execute in kernel space they are particularly low level pieces of software and thus are more difficult to compose than code that executes at higher levels, this is largely because it is not possible (generally) to utilize external libraries. This increases both code length and complexity. In light of this most kernel mode rootkits are developed as ‘drivers’, specifically device drivers, as this is done outside of nefarious reasons and is thus relatively documented and doesn’t require as much knowledge of the operating systems kernel. This is of particular importance to windows operating systems as the kernel source is not public.

A ‘authentic’ device driver is a program which is typically used to operate or handle a specific type of device which is connected to the system on which it is deployed. It forms a link between hardware and software and is thus classified as a ‘software interface’. As device drivers communicate directly with hardware and must operate differently on different kernels they must be developed with a narrow target scope in mind.

Another critical feature of kernel mode rootkits is that they can take advantage of ‘Direct kernel object manipulation’ (DKOM). DKOM is specific to Windows operating systems, but has a sister concept in linux kernels which ultimately performs the same actions. DKOM aims to hide the rootkit and any other malicious/nefarious articles installed/added to the host system, from the task manager and event scheduler, and on linux the system call table, by modifying the linked-list (abstract data structure) which catalogs all active threads and processes which are running.

## Side Note on Rootkits

At this point I have looked ‘extensively’ at two types of rootkits, perhaps giving the false perception that these are the only types of rootkits in existence. There are in fact a number of other rootkit types which are implemented/deployed at even lower levels than kernel and user mode rootkits. Bellow is a summary of these rootkits:

**Bootkits**

Infects OS startup code executing on system reboot, because it executes from the boot sector it can also perform full disk encryption

**Hypervisor level**

Runs in ring-1 on top of the kernel, hosts a VM operating system from which it can intercept calls

**Firmware and hardware**

Execute from hardware firmware like motherboard BIOS, router firmware and expansion cards (network, PCI etc), can survive operating system rewrites and disk replacement

## Project Plan

Having read rather extensively about both of the options which were considered for the project a conclusion about the approach from here could be appropriately made. From here the focus will shift to developing a kernel mode rootkit for linux (linux kernel). This decision is based on a number of factors outlined below:

- Mandatory driver signing for Windows 64 bit architecture

  - Involves getting a certificate, which probably isn’t possible due to the nature of the project, in order to execute it in a proof of concept
  - A lot of extra effort to find a work around potentially

- Limited resources for windows rootkits & device drivers

  - Without any kind of concrete (up to date) resources to reference during the development the time to develop the rootkit will be dramatically increased, further the main documentation located for developing windows device drivers was produced by microsoft themselves and lacks the details needed to port the concepts their to malicious rootkit methods

- Availability of Linux resources
  - With the linux kernel being open source it is significantly easier to learn about and locate resources for Linux driver development
  - There is also up to date kernel mode specific rootkit resources
