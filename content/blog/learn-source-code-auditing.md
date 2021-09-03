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


Weather a audit is black box or white box also influences what strategies are used and how effective those strategies will be. There are two main categories of analysis; dynamic and static.


## Dynamic Vs Static




## Top Down Vs Bottom Up

## Automating Source Code Audits