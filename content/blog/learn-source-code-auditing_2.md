---
title: "Learn Source Code Auditing By Building a Tool #2: POC and Pattern Analysis for Basic Vulnerabilities"
categories: ["Hacking", "Source Code Auditing", "Binary Exploitation", "Code Review"]
tags: ["hacking", "Source Code Auditing", "Exploit Development", "Static Analysis"]
date: "2021-09-23"
type: "post"
weight: 400
keywords: "hacking pentesting c source code auditing static analysis"
---

I already rambled about what source code auditing is, why we do it, and its pros vs cons over dynamic analysis. So in this post I'll present some basic vulnerabilities we can look for in audits and how we might build a tool for their detection using simple pattern matching and rules.

## Key Terms

+ Signature: An encapsulating term to refer to both a set of rules and a description of what the rule aims to detect and why the matching of such a rule could indicate the presence of a vulnerability
+ Rule: A regex pattern with a specific detection goal under a particular signature
+ Regex: Regular expressions are a way of specifying a search pattern particular for natural languages

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

[Format strings](https://secsheets.cybernetic.coffee/binary-exploitation/formatstrings/) are an excellent detection to start with. Firstly because they are simple, narrowly scoped, missuses of common and familiar `C` apis. Secondly because their 'rareness' in the wild (nowadays) is characterised by the phrase. 

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

Next we will construct the main detection module that will use our defined rules to hunt for offending source code block. Rather than just pasting all the code that can be found on [GitHub](https://github.com/Angus-C-git/csifter/tree/7b2b5ca6ddfaf6bbb55349221ef4f1c477bae3c9), the approximate commit for this blog is linked, I will just explore the key snippets that implement our desired functionality. 

*Note that the functions presented here are from the latest version of the code so some function names and variables have changed to support cli args, but the purpose of the code is largely the same.*

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

The role of this function is to extract each signature and rule from the database and trigger a pattern based search for this rule in the current target source code file. Then for each of the source code lines matched (blocks) a array of blocks to present to the auditor is constructed. The function the hands off these blocks to the UI report component to handel.


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

The `search_pattern` function is the main utility for the tool. It performs a regex search using the `regex` module which is not the same as the inbuilt python regex module. Of note is that the `regexsearch` function is actually the `finditer` function from this module, `from regex import finditer as regxsearch`. The reason 
we want to use this variation of the find function is that their could be multiple detections for the same 
rule in one file.

The `resolve_block` function handles taking a matched result from the pattern search and extracting the relevant source code syntax snippet and line information from the target file for use in the report interface.

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

The `render_block` function is key driver for the audit report that is generated for auditor consumption. It
utilises rich's panel, syntax and markdown rendering capabilities to combine the information from the signature description, source code syntax snippet and line information, to construct a HUD element which displays key information to the auditor to quickly diagnose the offending code. 


## Writing Tests to Ward Off Falling into the Debugging Abysses 

<!-- Regression tests and methodology -->

Now lets quickly talk about writing some tests with [pytest](https://docs.pytest.org/en/6.2.x/) and why we might want to do something so satanic. Note that I actually wrote the test cases for the functionality presented here in a later commit, [here](https://github.com/Angus-C-git/csifter/tree/87a13319a59300b4f1a48e07b6016006ac3edfa4/tests) so check that out for complete context. 

Typically when we make software especially me - a complete novice -, we hack away at a project making rapid progress at times and then slowing down at others while we solve a problem. By the time we finish such a cycle we probably have something that works against a little test input that we wrote but does it hold up against all the inputs the program could receive?

This is where unit testing comes in, we insure that each discreet module of the program can withstand the full variety of inputs it may be exposed to. This involves:

+ Testing all paths data can take through the 'unit'
+ Testing all the branches in the unit itself
+ Ensuring the test data allows the above to happen

The other reason we want to write tests is for what happens when we return to a project that we have been hacking on and start working on a new feature or module. Its easy to plough forward working on something against a new little test case only to come back and find that the original feature now doesn't work as expected. Writing tests to ward against this 'backwards progress' is called **regression** testing.

One useful thing I discovered while doing this is that we can keep our tests completely separate to csifter's logic and create all the tests in a top level directory while still being able to access the necessary internals we want to test with imports. To do this we need to structure the project as follows, importantly adding a `__init__.py` file to the tests directory so that python will recognise it as a module.

```
.
├── csifter
│   ├── database
│   ├── __init__.py
│   ├── sifter.py
│   ├── ui
│   └── util
├── sift
└── tests
    ├── __init__.py
    ├── modules
    └── test_fmtstrings.py
```

Then inside our test file `test_fmtstrings.py` we can simply import the csifter internal functions we want to test with conventional imports.

With pytest, and probably any testing library at all, we write tests by first submitting a test case and then **asserting** something about the returned data that the functions we are testing produce. The assertion we make should support what we expect the functions to do under certain conditions determined by the **test input**.

In this case I decided to write `C` files with specific detection cases and edgecases such as variations in syntax and formatting and then check that the core sift function returned the right number of detections based on my manual analysis and that the matched starting line numbers corresponded to the actual starting lines in the original source file. 

Now this is not necessarily the best way to do this since:

+ If new test cases are added to the file without care for the existing tests then all the assertions will have to be updated
+ Only one function is directly tested, `sift`, which places a reliance on nothing going wrong in the helper functions that `sift` calls. Thus if the test reported a failing case we could not be certain that it was caused by the sift function directly or one of the helpers. 

However, in this case it should be pretty easy to triage the source of any errors since the functions `sift` calls are directly responsible for a particular assertion. For example if a line number is wrong but the number of matches returned is correct that means that the problem **should** lie in the function that resolves line numbers for detected blocks. Further, should we want to add more test cases we could potentially just ignore the formatting of the test `C` file and just append the cases to the end of the file which would not interfere with the previous assertions. 

Thus we end up with the following simple test.

```python
import pytest

# CONFIG
from csifter.sifter import sift
fmtstrings_test_file = './modules/fmtstrings.c'  
vulnerable_lines = [
	42, 65,
	43, 68,
	44, 72,
	45, 76,
	46, 80,
	47, 85,
	48, 90,
	49, 95,
	53, 104,
	54, 108,
	57, 114,
	58, 117,
	59, 121,
	60, 125,
]


def test_fmtstrings_found():
	found_blocks = sift(fmtstrings_test_file)
	assert len(found_blocks) == 28


def test_fmtstring_src_ref():
	""" test the lines format string
	vulnerabilities were identified on
	"""
	blocks = sift(fmtstrings_test_file)
	
	for block_no, line in enumerate(vulnerable_lines):
		assert blocks[block_no][1] == line
```

We can now execute all the tests simply by running `pytest` in the `tests` directory providing a near instant method to check that new code added doesn't break existing functionality.

## Technologies

Here's a list of technologies used in **csifter** and some assistive tools for development of the regex rules.

+ [Rich](https://github.com/willmcgugan/rich) - rich is a python library for building better cli outputs and prettifying information presented to users
    + cisfter relies on rich for syntax highlighting and panel construction for the final output as well as the ability to use markdown 
+ [Regexer](https://regexr.com/) and [regex101](https://regex101.com/) - are similar sites that allow you to develop regex patterns and receive instant feedback of how they will perform in practice by supplying a test file to apply the pattern to 
    + I used this to design the regex patterns that make up the detections
+ [pytest](https://docs.pytest.org/en/6.2.x/) - is a testing framework for python 
    + We use this to ensure that we don't break existing functionality as we move forward and properly test new modules
