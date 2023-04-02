---
title: 'Hello Kernel'
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

How can we integrate our rootkit into the kernel? How does the Linux kernel work regarding drivers? What does driver code look like? Where can we debug a Linux driver at runtime?

This week looks at what it takes to get a rootkit running on the ubuntu (and forked distros) Linux kernel and highlights the way in which rootkits are engineered for specific operating system kernels. Initially we investigate entry points in the ‘kernel land’ and why drivers help us handle the monolithic kernel. Then we take a detailed look at writing and debugging basic kernel driver programs with a practical walkthrough of some source code.

## Integrating rootkits into the Linux Kernel

The Linux kernel is well into its 5.0 version now and has surpassed 26 million lines of code, primarily written in C. Finding an entry point into this monolithic kernel (monolithic architectures are ones where the entire operating system runs within the kernel) is therefore an extensive task even for experienced C developers. It is for this reason that the majority of kernel mode rootkits enter kernel land as drivers. As discussed previously drivers are inherently trusted by the operating system and are installed as trusted programs by the root user (not including userland rootkits), furthermore, drivers are a reasonably well documented (sample code) phenomena as they are typically developed by ‘third parties’ to the operating system (for example a printer drivers).

## Drivers in Linux

Drivers in Linux are a type of loadable kernel module (LKM). LKMs are a type of object file which extend the functionality of the ‘running kernel’. LKMs are a necessary part of Linux operating systems as without them the kernel would need to anticipate all required functionality, for example how every printer, peripheral and the like would interface with the system. LKMs are not built into the kernel and therefore must instead be inserted into the kernel at runtime, either manually through commands like `insmod` or `modprobe` or through some program. Injecting LKMs, therefore, typically requires root privileges and is the reason the deployment of rootkits must rely on privilege escalation or other techniques to gain root privileges. LKMs in linux, when compiled, appear as “.ko” files which stand for ‘kernel object’.

## Writing and Debugging Linux Drivers

> [Source Code](https://github.com/AngusCornall/VERTO)

Since we are writing a driver which will run in the kernel space we cannot compile and run it as a normal C program. Instead we must use/work with existing files (which can be programs in linux {everything in Linux is a file}) from the kernel we are working with in order to interact with the operating system. These will manifest themselves in our C code as ‘#include’ tags at the top of our file.

```C
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
```

The above include tags point to various header files in the kernel that we need for our driver, namely the module header gives us access to the module interface to the kernel (all modules must have this), the kernel header (kernel.h) file lets us output debugging messages (like a console normally) to the kernels log file (which displays information about running processes in kernel space), using `KERN_INFO` specifically. The final header file, “init.h” is not technically necessary for driver creation&semi; it was added post kernel version 2.4 (Linux 2.4) and gives us access to some macros which are defined there. These macros allow us to run ‘nicer’ kernel clean up functions (freeing kernel memory), that is operations that incur when we insert and remove our module (for now).

Next we will write a ‘Hello World’ program which captures the central components of a simple module program.

![sketchy diagram](https://lh6.googleusercontent.com/DaNPnh29W2H_5LZPENqYkrfHCGdHbWWavxupRE68tYMTfPQAk5Yi5xjMoLs0W8LqzvCgMQHwMoOtB3x6y6Chmni4fXQwTtmjhTpteuTieH5nm2JjXBf7utYbum1qg4Qlp7wb7vnN)

> sketchy source code diagram

As outlined above, module programs have two main functions: an entry function which is triggered when the module is inserted into the kernel and an exit function which is called when the module is removed. Take note that `printk` replaces other well known C print functions like `printf`, `printk` is specific to the Linux kernel and is defined in the kernel header file. As of kernel 2.4 the notion of kernel module signing was introduced, largely thanks to chads who work on the Linux kernel, to help avoid licencing issues and non-open source code. Slightly funny considering we are developing a rootkit, but we introduce the `MODULE_LICENCE()` macro to remove some of the taint warnings we get during compilation.

Finally let's look at what happens when we compile and run our module. Oh yeah and the make file …

```make
# target file
obj-m += helloworld.o

# used to reference this make action from cli
all:
    # we use a bash snippet inline to pull kernel-header versioning info
    # dynamically
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:

	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

We use the Make file to make compiling our module more convenient, take note of the shell code uname -r which returns the systems kernel name and version for example:

`5.4.0-3parrot1-amd64`

> See the [last section](#bonus-dev-setup) for more exploration related to this

To compile our code we run the following:

```bash
make all
```

We will then see several new files in our directory, including the “.ko” ‘kernel object’ file which we will insert and run with the following command:

```bash
sudo insmod helloworld.ko
```

As you can see the `insmod` command, which stands for insert module, must be run with root permissions via sudo here. Before we insert the module however we should also open the kernel log or syslog file to see the debugging output (“hello world”) from our entry function. To do this we open another prompt and run:

```bash
tail -f /var/log/syslog | grep DEBUGGER
```

The `tail` command outputs the last 10 lines of a file, adding the tack f flag (`-f`) will show the last 10 lines of the file and monitor updates to it displaying them as it changes. The pipe grep (`| grep`) allows us to view only additions to the log that come from our module (via our KERN_INFO calls). Now running the insmod command produces:

![output](https://lh3.googleusercontent.com/3gxDlbglCLrHZNrI4aN2866P_BsIIhgH8N7Dd8Iert1WfXOJtdUzfCLHZs9X6gJ7Coqj4yXh0fBi3jq_OsR3hyz9sIYaDmQ3462NUJa0yb7oQ2WLIGJy3w8R6lrG0W4dkLE3JnDy)

To remove our module and trigger the exit function we use the `rmmod` command:

```bash
sudo rnmod helloworld
```

Which appears in our log monitor as:

![command result](https://lh3.googleusercontent.com/_sg9oaIPdxxnxS-OrEAbgiMqeD4Ifdu6IduECLEi-iapjwQ_PILnbq0jiiNHZWLEC3yGR-J2g-JMjbdt0p6bLzpwhitLKnn4Ry9aYyMp6lvvMhrPit3wb8oUx2IlTMTqboKEzuXx)

Completing our Hello world program.

## Bonus: Dev Setup

Due to some classic -expletive- I could not get any module code working on my host operating system ‘Parrot Security OS’ which is forked from Debian. The target OS for the project was Ubuntu regardless but considering Ubuntu is forked from Debian also I was relatively confused about what was going on. My current understanding is that it is probably a pathing issue with the header files being located in a different place on Parrot. I am yet to test if it works on Debian itself. The main difference is that the uname -r presents as ‘generic’ on Ubuntu and on Parrot as ‘parrot1-amd64’ (shown above) and therefore I think the header files are in completely different directories which is a bit weird. Nevertheless I have instead set up a virtual implementation of the latest version of Ubuntu on Virtual Box and things have been going smoothly there.
