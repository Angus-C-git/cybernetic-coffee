---
title: "Learn Source Code Auditing By Building a Tool #2: POC and Pattern Analysis for Basic Vulnerabilities"
categories: ["Hacking", "Source Code Auditing", "Binary Exploitation", "Code Review"]
tags: ["hacking", "Source Code Auditing", "Exploit Development", "Static Analysis"]
date: "2021-09-02"
type: "post"
weight: 400
keywords: "hacking pentesting c source code auditing static analysis"
---

I already rambled about; what source code auditing is, why we do it, and its pros vs cons over dynamic analysis. So in this post i'll present some basic vulnerabilities we can look for in audits and how we might build a tool for their detection using simple pattern matching and rules.

## What are we Building?

In this post i'll start building what will become the primary vulnerability detection model. That is the signature and pattern matching logic for **csifter**, a grep style source code auditing tool for `C` code bases.

By the end we will end up with a cli tool that can produce output like the following.

{{< image ref="images/blog/src_audits/csifterBasicPOC.png" >}}


Okay so how does this 'pattern' matching and signature based detection work. In our case to keep the tool simple and flexible we want to avoid building abstract syntax trees or the like. So instead the core of our detection model will be handled by database of **regex rules**.

Unsurprisingly this is very much the way graudit operates too. Bellow is a snippet of the `c.db` file.

```
printf[[:space:]]*\([[:space:]]*[^\,\'\"]+[[:space:]]*\)[[:space:]]*\;
sprintf[[:space:]]*\([^\,]+,[^\,]+\%s
.?scanf[[:space:]]*\([^\,]+\%s[^\,]+\,[^\,]+\)\;
strnc(py|at)[[:space:]]*\([^\,]+\,[[:space:]]*[^\,]+\,[[:space:]]*sizeof\(
memcpy[[:space:]]*\([^\,]+\,[^\,]+\,[[:space:]]*sizeof\(
[[:space:]]gets[[:space:]]*\(
^[[:space:]]*gets[[:space:]]*\(
exec(ve|l|lp|le|v)[[:space:]]*\(
system[[:space:]]*\(.+\)\;
malloc[[:space:]]*\(.*strlen[[:space:]]*\(
(strn?c(at|py)|memcpy|sn?printf|scanf)[[:space:]]*\(.*(arg|getenv)
strnc(at|py)[[:space:]]*\([^,]+,[^,]+,[[:space:]]*strlen[[:space:]]*\([^\)]+\)[[:space:]]*\)
malloc[[:space:]]*\(strlen[[:space:]]*\(.*\)
\[[0-9][0-9]+\].*=.*\\0
\[[^\]]+\+[^\]]*\].*=.*\\0
snprintf[[:space:]]*\([^\,]+\,[[:space:]]*sizeof\(.*\%s
strncpy[[:space:]]*\([^\,]+\,[[:space:]]*sizeof\(
memcpy[[:space:]]*\([^\,]+\,[^\,]+\,[[:space:]]*sizeof\(
memset[[:space:]]*\([^,]+,[^,]+,[[:space:]]*0[[:space:]]*\);
```

Of interest here however is that graudit will detect on **any** usage of the APIs it has rules for in its database. For example consider the following `c` source code.

```
void
main()
{
    char * message = "because im static and formatted";
    
    printf("Im safe %s\n", message);
}
```

If we run graudit against this file using the `C` signatures we will get the following output.

{{< image ref="images/blog/src_audits/grauditFalseOut.png" >}}

In this case the use of `printf` in this way is perfectly safe and no risk of a format string vulnerability is present. This is the nature of graudit. It is a tool to highlight potential areas of the code where some kind of unsafe functionality could occur rather than areas of high likelihood. Thus it is more of an assistive tool that may help spot some issues quickly or avoid large segments of uninteresting code (safe code). 

We will seek to improve on this by focusing on writing rules that can detect 'definite', or to a high degree of certainty, vulnerable usage of APIs, and otherwise distinguish between a warning for potential risk vs likely risk.

Another area that I find lacking with graudit is that it does not provide any explanation or reasoning as to why the detection was triggered or what to look for/check to see if the particular signature triggered corresponds to a vulnerable usage. This tool takes the assumption that the auditor already has knowledge about safe usage of APIs and can distinguish between safe use cases and vulnerable ones. This tool is of little use to a developer who wants assurances that their code does not contain trivial vulnerabilities or risks or to the security researcher who is not well versed in `C` based vulnerabilities risks. Thus in our tool we will seek to provide explanation of, the particular rule, why it was triggered and under what circumstances the detected 'block' would be vulnerable.

## Making the POC
<!-- Making a POC -->

Now we may start building things out. A logical place to start is with the 'rules database', the regex patterns that will be used in matching to create detections. 

<!-- 
 + signatures  = regex patterns
 + grepping as a technique
 + making it more useful to the uninformed researcher or developer
    + descriptions, context

-->

## Writing Tests to Ward Off Falling into the Debugging Abysses 

<!-- Regression tests and methodology -->

## Technologies
<!-- rich -->

<!-- gcc -->

<!-- regexer || regex101 -->

<!-- pytest -->