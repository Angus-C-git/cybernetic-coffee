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

Static analysis is of course the preferred choice for white box testing situations where the source code is provided in its natural state. We take the programs file(s) and we scan over its contents looking for mistakes assisted by manuals and potentially other tools like the one we will start building [next](#). No data is input to functions or the contents of variables examined in a debugger but rather how a function will behave under various conditions is theorised by the analyst. Being able to see how everything in a program links up like this is obviously very useful and is the reason we build tools like [dissassemblers](#https://en.wikipedia.org/wiki/Disassembler) so even in a black box setting, provided we have the executable program, we could examine a representation of its source code. 

Perhaps you have already started forming ideas abut the drawbacks of each approach but ill summarise some of the ones i've thought about.

**Dynamic Analysis**

+ Pros
   + Its more natural to process logic by testing it and observing the results
   + This process can be automated with tools like fuzzers
   + Its easier to track testing/analysis coverage 
   + Its easier to trace where user controlled data ends up / interacts with

+ Cons
   + Its easier to miss potentially vulnerable logic
   + It can be time consuming to examine the entirety of a program only being
     able to move through it in a linear fashion
   + Vulnerable input data may go untested even n automated settings
      + For example the [sudoedit](https://liveoverflow.com/critical-sudo-vulnerability-walkthrough-cve-2021-3156/) vulnerability which went undiscovered for years

**Static Analysis**

+ Pros
   + Its eaiser to get an overall picture of the programs internals and how they connect
   + Its easier to find simplistic or well known bugs/errors/vulnerabilities  
+ Cons
   + Its more difficult to trace user controlled data through the program
   + Its more difficult to predict how complex logic will perform under certain input conditions

## Top Down Vs Bottom Up

With the prerequisites out of the way lets start drilling into static source code analysis methodologies. When talking about source code auditing two approaches are typically thrown around; the top down approach and the bottom up approach.  

### Top Down Approach

+ Find and collate all external entry points into the program
   + System input
   + User input
   + Network input
   + Other external data interactions
+ Start analysis from these points and follow where externally controlled data goes
+ How can external inputs change the flow of program execution and what branches are exposed
+ Check if that data properly sanitised and how it gets used with various APIs

### Bottom Up Approach

+ Start at the programs entry point
+ Work out where execution can diverge from here
   + What functions are called
   + What conditions expose different program logic
+ Analyses these blocks how does data from the entry point end up there and does it result in any security risks
+ The principle of locality dictates that a program will spend most of its execution time in the same region, this region also tends to be the most secure, 
  so look to see how the program can be made to divert from its mainline
  and if vulnerabilities are exposed on these less common execution paths

## Automating Source Code Audits

Vulnerabilities uncovered in source code audits range from trivial api misuse to subtle one byte overflows and race conditions. Automated static analysers and pre-compilation analysis tools can detect these different security risks 
with varying degrees of success. In most cases these tools will operate with a high yield of false positives and rely on the auditor to separate these from the real vulnerabilities. This is a key point, **automated tooling is not effective
enough** to eliminate the need for manual analysis and testing! Let's take a look at some of the tools that exist and their various strengths and weaknesses. 

### GCC

The gcc compiler is a source code analysis hybrid that few people consider when thinking about static analysis. If you have ever tried to create a purposely vulnerable program in `C` using something like the `gets` function then you have likely seen gcc warn you that this is a security issue and that `gets` is deprecated. But gcc can also perform more powerful things that we take for granted such as detecting buffer overflows when working with statically sized buffers or type overflows. If you think about how you would do this with purely static analysis you may come to the conclusion that you would't or shouldn't, and in fact this is not how gcc does it. Since gcc is a compiler at heart it constructs what's called an 'abstract syntax tree'. This is *basically* a way of tokenising the different keywords from the syntax and organising them as a tree which represents the 'logical structure' of the program as a tree. This in, assumed, combination with other compiler features allows gcc to detect that a particular operation will overflow a buffer and even by howe much. Of course gcc is not perfect and can not detect all security issues in fact it can only really detect a small subset.


+ **strengths**
   + Low false positive rate
   + Automatically runs at build time   
   + Can generally detect more complex bugs that pure static analysis tools
   + Generally good at detecting bad api usage
   + Good coverage

+ **weaknesses**
   + Does not cover many vulnerability classes
   + Tends to miss some obvious bugs
   + Focuses on warning about near certain flaws rather than potential risks

### Clang Static Analyser

*Note: here I refer to the CodeChecker tool in the clang static analyser suite*

The clang static analyser is basically a roided up version of gcc's analyser. It is designed to be integrated into a projects build chain where it collects "compiler calls and saves commands in a compilation database". This 
database can then be used to feed the analysis tool `CodeChecker` which uses `clang` regardless of the compiler originally used to analyse the sources against another database of signatures which represent bad practice and
potential security risks. It then generates a CLI or static HTML report for consumption which includes a:

 + Brief description of the identified signature
 + Severity/risk score 
 + Review status

among other items shown bellow. 

{{< image ref="images/blog/src_audits/clang_static.png" >}}

I've not really used this tool before so there's no value in me really weighing up strengths and weaknesses but I like that it includes a description message and a severity rating.  


### linter's

It's worth mentioning that linter's are also a familiar form of static analysis they can tell us about syntax mistakes and api missuses before compilation or runtime. However they are more geared towards 
syntactic issues over security ones.  

### graudit

grudit or 'grep audit' is a grep styled static analysis tool which focuses on assisting the auditor by providing a 'list' of potentially interesting/vulnerable points in the source. It does so by using a set of 
regex rules which it refers to as a signatures to match patterns in supplied source code. One of the main benefits of graudit is that it supports many languages and can be easily extended by adding more rules. This
however does come with other drawbacks.  

+ **strengths**
   + Flexible, lightweight and extensible
   + Support for many languages
+ **weaknesses**
   + Huge degree of false positives
   + No explanation of why a rule was triggered or what it means
   + Limited rule sets for some languages, like `C`


## Our Tool

In the next post we will start building a simple tool similar to graudit but with extended features and a focus on C programs.


## Resources

+ [graudit](https://github.com/wireghoul/graudit/)
+ [clang CodeChecker](https://github.com/Ericsson/codechecker/blob/master/docs/usage.md)