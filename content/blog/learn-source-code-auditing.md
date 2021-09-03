---
title: "Learn Source Code Auditing By Building a Tool #1: Static Analysis for the Dynamically Paralyzed"
categories: ["Hacking", "Source Code Auditing", "Binary Exploitation", "Code Review"]
tags: ["hacking", "Source Code Auditing", "Exploit Development", "Static Analysis"]
date: "2021-09-02"
type: "post"
weight: 400
keywords: "hacking pentesting c source code auditing static analysis"
---

Source code auditing/analysis is like taking the blueprint for a car and trying to find flaws in the design before it is ever built and sold to the public. This has advantages over just testing the car once it has been manufactured but is not without flaws. It's much easier to miss things when presented with a massively complex system whose operations may only be visualized or imagined. Of course it is also possible to have both a fully constructed model and a blueprint with which to audit the car for flaws. Unsurprisingly this is the best method, one can look at a aspect of the blueprint and then examine it as a part of the larger system, they can easily visualize what other components interact with the current subject of analysis and make testable hypothesis. Now lets port this budget analogy to auditing program source code.


## Black Box Vs White Box

The first distinction we will make is the difference between black box and white box audits. This is the same distinction as **having** the source code or **not having** the source code. Typically having the source code of a program means we can also build it and test against the built program as if we did not have the source but the strength of white box testing is being able to quickly classify large blocks of a program as safe which is often more difficult/time consuming in a black box setting. 

In whitebox settings we attempt to identify problems in the source code that will likely lead to the exposure of a vulnerability in the compiled code. [Next post](#) will start talking about such problems and detecting them.


**White Box Testing**

+ pros
   + Quickly distinguish between sections of a program which are likely to be safe vs areas of interest
   + Easily spot simple programming mistakes
+ cons
   + Can be harder to get an overall sense of what a program does
   + More difficult to predict how certain data will behave against parts of program logic 


**Black Box Testing**

+ pros
   + Discovered vulnerabilities more likely to be exploitable
   + Easier to detect configuration issues
+ cons
   + Harder to unravel program logic
   + Harder to detect simple programming mistakes  


Weather a audit is black box or white box also influences what strategies are focused on and how effective those strategies will be. Typically we talk about two main categories of analysis; dynamic and static.


## Dynamic Vs Static Analysis

Dynamic analysis is probably the most familiar/natural to us when we think about understanding how something works. We try it out, play with it or modify it to understand how it works. In a computing this typically involves feeding different data to inputs, using the program in different settings or perhaps even debugging code in a debugger like gdb. Its easy for us as humans to experiment with various inputs and observe their outputs in order to understand how a program works or behaves under certain conditions. It is also common for dynamic analysis to be our only option for example when examining a remote target for which we have neither the executable nor the source code. Programs for which we have the obfuscated executable  may also lend themselves more to dynamic analysis. [Black Box Fuzzers](#), really any fuzzer, takes this idea of trying different data against a target and automates it on a massive scale trying and mutating thousands of input cases per second looking for data that may crash the program or cause it to act unexpectedly.  

Static analysis is of course the prefred choice for white box testing situations where the source code is provided in its natural state. We take the programs file(s) and we scan over its contents looking for mistakes assisted by manuals and potentailly other tools like the one we will start bulding [next](#). No data is input to functions or the contents of variables examined in a debugger but rather how a function will behave under various conditions is theorised by the analyst. Being able to see how everything in a program links up like this is obviously very useful and is the reason we build tools like [dissassemblers](#https://en.wikipedia.org/wiki/Disassembler) so even in a black box setting, provided we have the executable program, we could examine a representation of its source code. 

Perhaps you have already started forming ideas abut the drawbacks of each approach but ill summarise some of the ones i've thought about.

**Dynamic Analysis**

+ Pros
   + Its more natural to process logic by testing it and observing the results
   + This process can be automated with tools like fuzzers
   + Its easier to track testing/analysis coverage 
   + Its easier to trace where user controlled data ends up / inteacts with

+ Cons
   + Its easier to miss potentailly vulnerable logic
   + It can be time consuming to examine the entirety of a program only being
     able to move through it in a linear fashion
   + Vulnerable input data may go untested even n autoamted settings
      + For example the [sudoedit](https://liveoverflow.com/critical-sudo-vulnerability-walkthrough-cve-2021-3156/) vuln which went undiscovered for years

**Static Analysis**

+ Pros
   + Its eaiser to get an overall picture of the programs internals and how they connect
   + Its easier to find simplistic or well known bugs/errors/vulnerabilities  
+ Cons
   + Its more difficult to trace user controlled data through the program
   + Its more difficult to predict how complex logic will perform under certain input conditions

## Top Down Vs Bottom Up

With the prerequisites out of the way lets start drilling into static source code analysis methedlogies. When talking about source code auditing two approaches are typically thrown around; the top down approach and the bottom up approach.  

### Top Down Approach

<!-- TODO -->

### Bottom Up Approach

<!-- TODO -->

## Automating Source Code Audits


### GCC


### Clang Static Analyser


### Graudit