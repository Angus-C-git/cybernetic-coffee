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

```C
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


## The Signatures Database

Now we may start building things out. A logical place to start is with the signatures or 'rules database', the regex patterns that will be used in matching to create detections. 

To start building out these rules we need to think about four main things:

1. What are we trying to detect?
2. What characterises this detected item as 'vulnerable'
3. What edge cases or variations exist that a detection for such a vulnerability needs to take into account?
4. What are the limitations of the detection? When and how can/would it fail? 


**An example detection**

[Format strings](#) are an excellent detection to start with. Firstly because they are simple, narrowly scoped, missuses of common and familiar `C` apis. Secondly because their 'rareness' in the wild (nowadays) is characterised by the phrase. 

> "... they are trivial to grep for"

**The characteristics of a format string**

We now think about how a format string vulnerability presents in `C` source code. The obvious example is a typical misuse of the `printf` function by supplying a user controlled input directly without a format specifier.

```C
printf(user_controlled_buffer);
```

This misuse is generalisable however to the following vulnerable usage description.

> Any format family API which takes a user controlled argument directly in the place of a format specifier. 

As a rule, from which to build a detection, perhaps we could define it as,

> any time a format API takes a non-static (quote) argument in place of the format specifier argument the usage is potentially vulnerable. 

Now then to define a regex pattern for this rule we could first look to match format functions in source code and then check if the specifier argument for the function did **not** start with a `"` or `'` indicating a non-static argument. Thus the following regex pattern could work for the `printf` api.

```python
printf\([^\"\']+\);
```

Note, however, that the definition for the rule was carefully constructed. This is because not all format functions are created equally and some are not well known. Bellow is a list of format functions we will consider (I was not able to find more).

+ printf        
+ fprintf    
+ sprintf    
+ snprintf      
+ vsnprintf  
+ vsprintf   
+ vfprintf   
+ vprintf    
+ dprintf    
+ syslog     
+ vscanf     
+ vsscanf    
+ fscanf     
+ scanf      


An interesting one that often catches people by surprise is the `syslog` API for logging. It is also of interest because it manifests differently to printf in terms of argument arrangement. Consider the manpage reference for `syslog`.

{{< image ref="images/blog/src_audits/syslogMan.png" >}}

We note that a `priority` should be supplied as the first value which is an integer quantity and will thus not contain any `"` characters.

Thus we need to take into account the first argument in our regex pattern. There is also another edgecase we must consider for our patterns and that is **alternative syntax**. Not all programmers or codebases are the same and the way a function call ins structured can change. For example consider the following alternative way of calling the `vsnprintf` API.

```C
vsnprintf(
        tmp, 
        0x100, 
        argv[1], 
        NULL
    );
```

If we try to simply apply a rule like the one we used for `printf` it will fail when things are split over multiple lines or a space proceeds the bracketed arguments. Hence we would define our regex pattern for `vsnprintf` to look more like the following:

```python
"vsnprintf[ ]*\([^\,]+\,[^\,]+\,[^\,\'\"]+\,[^\,]+\);"
```

In terms of code/project structure I define these regex patterns in a file called `db.py` and store the rule along with a name and description in a JSON like python object. The bellow is a snippet of the file showcasing the rules and description for the format string detections.

```python
signatures = [

    {
        "name": "Format String",
        "description": "An variable is supplied directly to the format argument of the  function, " +
                       "if the variable is user controlled a format string exploit my be possible.",
        
        "rules": [
            #printf
            "printf[ ]*\([^\,\'\"]+\)\;",
            "fprintf[ ]*\([^\,]+\,[^\,\'\"]+\);",
            "sprintf[ ]*\([^\,]+\,[^\,\'\"]+\);",
            "vprintf[ ]*\([^\,\'\"]+\,[^\,]+\);",
            
            "snprintf[ ]*\([^\,]+\,[^\,]+\,[^\,\'\"]+\);",
            "vsprintf[ ]*\([^\,]+\,[^\,\'\"]+\,[^\,]+\);",
            "vfprintf[ ]*\([^\,]+\,[^\,\'\"]+\,[^\,]+\);",

            "vsnprintf[ ]*\([^\,]+\,[^\,]+\,[^\,\'\"]+\,[^\,]+\);",

            # logging 
            "dprintf[ ]*\([^\,]+\,[^\,\'\"]+\);",
            "syslog[ ]*\([^\,]+\,[^\,\'\"]+\);",

            # scanf
            "scanf[ ]*\([^\,\'\"]+\);",
            "fscanf[ ]*\([^\,]+\,[^\,\'\"]+\);",
            "vscanf[ ]*\([^\,\'\"]+\,[^\,]+\);",
            "vsscanf[ ]*\([^\,]+\,[^\,\'\"]+\,[^\,]+\);",
        ]
    },


    # <snip>
```

Defining things in this way means that when we build the functions that use the rules to match parts of target source code we can also include **useful** a description in the UI module explaining why the rule was matched and what makes the detected usage a risk. 

## Making the POC

Next we will construct the main detection module that will use our defined rules to hunt for offending source code block. Rather than just pasting all the code that can be found on [GitHub](#), the approximate commit for this blog is linked, I will just explore the key snippets that implement our desired functionality.

**sifter.py**

The sifter module is the core of the csifter tool. It reads the patterns from the signature database and greps through the target source code file for matching results. The entry point to this module is the `sift` function.

```python
def sift(target, limit=None):
    """ 
    pass over target file searching for
    source code which matches a rule.

    target: the path to the current
            candidate for source analysis
    """
    blocks_of_interest = []
    for signature in signatures:
        for rule in signature['rules']:
            results = search_pattern(rule, target)

            if (
                limit is not None 
                and len(blocks_of_interest) >= limit
            ): break

            for match in results:
                blocks_of_interest.append(
                    resolve_block(signature, match, target)
                )

    # render blocks
    render_blocks(blocks_of_interest)
    return blocks_of_interest
```

<!-- TODO  -->


```python
def search_pattern(rule, target):
    """ search src file for rule """
    with open(target, 'r') as src:
        return regxsearch(rule, src.read())


def resolve_block(signature, result, target):
    """ 
    creates a block which encapsulates
    the affected code.

    block:
        signature: the rule that matched
                   the source code block
        line_no: the line where the 
                 identified block 
                 starts
        snippet: the source code which
                 was matched by the rule
    """
    with open(target, 'r') as src:
        line_no = src.read()[:result.start()].count('\n') + 1
        snippet = result.group()
        return (signature, line_no, snippet)
```

<!-- TODO  -->

**`ui/report`**

```python
def render_block(data):
	""" render the potentially vulnerable code block """
	snippet = data[2] 
	title = data[0]['name']
	description = data[0]['description']

	code_snippet = Syntax(
						snippet, 
						SYNTAX, 
						theme=THEME, 
						line_numbers=True, 
						start_line=data[1]
					)

	description_txt = Markdown(
			f""" ## Explanation \n {description} """,
			inline_code_lexer=SYNTAX,
			inline_code_theme=THEME,
		)
	
	components = RenderGroup(
					code_snippet,
					description_txt
				)
	
	block = Panel(
			components,
			title=f'[b white]{title}',
			width=60,
			border_style='red1'
		)

	# render
	print('\n')
	print(block)
```

<!-- TODO  -->

## Writing Tests to Ward Off Falling into the Debugging Abysses 

<!-- Regression tests and methodology -->

## Technologies
<!-- rich -->

<!-- gcc -->

<!-- regexer || regex101 -->

<!-- pytest -->