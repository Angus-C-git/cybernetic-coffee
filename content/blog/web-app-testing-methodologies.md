---
title: "Web Application Testing Methodologies"
categories: ["Pentesting", "Hacking"]
tags: ["Pentesting", "Hacking", "Web App Testing"]
date: "2021-01-06"
type: "post"
weight: 400
keywords: "blog Hacking Pentesting Web App Security"
---

## Testing Modern Web Applications

The modern web application is a mass of complex interwoven components neatly hidden away behind a clean and
responsive user interface (UI). But once you start unplugging the cords from the frontend framework the scope of
the application becomes clear, the attack surface large. In a world where testers are increasingly short on time and/or
daunted by the scope of vulnerabilities to test for how can we ensure coverage without forfeiting time?

{{< image ref="images/blog/the-modern-web.svg" >}}

{{< md_html >}}
    <p style="text-align: center">
        <b>[A Modern Web Application]</b>
    </p>
{{< /md_html >}}

## The First HTTP Request

Where to start? This is really the important question to be asking for me since it shapes how you
continue into later stages of testing. How then do I start?

As a **user**.

Not as your typical user trying to figure out how to view a certain piece of information or complete
a desired task, but as a developer. A developer, specifically, with a critical and skeptical mind 
using your security eyes to identify areas of the application you are testing that may be weak or that
behave differently to how you expect. 

Exploring the web app you are testing from this perspective ensures that you have a good understanding of
the web application including its; purpose, likely tech stack, typical workflow and authenticated areas.

This process can be enhanced by running Burp Suite in the background as you browse, passively collecting endpoints
and request bodies to investigate further. Coupling this with a browser plugin like [wappalyzer](https://www.wappalyzer.com)
and using the developer console while you navigate through the application can provide valuable context and insight
into the application. 

### Opening Summary

*'Just like in chess the opening can make the difference between winning and losing the mid-game.'*

‣ Run burp passively in the background   
‣ Explore the web app as a critically thinking developer   
‣ Use tools like [wappalyzer](https://www.wappalyzer.com) to fingerprint the application   
‣ Have developer tools open looking for:

+ Warnings,
+ Errors
+ Left over debugging logs, 
+ Tokens in storage
+ Libiary Version Numbers

## Analysing The Board 

Equipped with a decent understanding of how the web application works it's time to start uncovering the full attack
surface. 

### Open Ports

Everything that connects to the internet operates on a specific port or group of ports. You can think of a port as one 
door to a castle.

A castle will typically have one or two big, well-defended doors and most of the traffic to and from the castle will happen 
through these doors. However, this does not mean that these are the only doors to the interior of the castle. Perhaps 
there is a secret door for the Lord for the castle to come and go as he pleases or a tunnel into the forest.

The same is true of a web application. The majority of data moves through one or two well established and defended ports. 
Most website traffic goes through the ports 443 (HTTPS), which you may recognise as the lock icon on most modern browsers, 
and 80 (HTTP). However, these sites are hosted on a server like anything else on the internet and can have other ports open. 
Open ports are like the doors on a castle that are open or unlocked, the castle may have other doors that are locked and 
not used, and these are the equivalent of closed ports.

Closed ports on a server will not accept any inbound traffic and are thus generally not useful to us. The open ports will 
always include the main ports used to communicate with that service, but they will often be accompanied by other open 
ports used for administration or behind the scenes' functionality. As with hidden but open castle doors, these ports are 
generally the easiest way into the internal infrastructure of many services.


{{< image ref="images/blog/web-app-castle.svg" >}}

{{< md_html >}}
    <p style="text-align: center">
        <b>[A Web Application As A Castle]</b>
    </p>
{{< /md_html >}}


### Port Knocking With Nmap

Running a nmap scan while you make a cup of coffee can occasionally reveal some additional layers to the web application
and expose services which may be vulnerable to simple attacks or CVE. A trusty nmap command string,   

`nmap -sC -sV -OA <target-ip> -p- >> <save file>`

is often more than enough to uncover a great deal of useful information about the kinds of services hanging off the
web application backend. 

### Subdomains

Domain names are human-readable pointers to servers on the internet, it is the job of the DNS server to resolve these
lexical names into the 'machine' name for the server. These machine-readable names are IP addresses. Domain names have
the following structure:

{{< image ref="images/blog/domain-name-diagram.svg" >}}

{{< md_html >}}
    <p style="text-align: center">
        <b>[Domain Name Structure]</b>
    </p>
{{< /md_html >}}

These Sub-domains commonly prove to be a weakness in web applications. This is because these subdomains can often 
receive very little traffic and are thus not considered a security priority. There is also a false sense of security
that stems from the school of thought that if the domain name isn't listed publicly or appears on search engines
then it is hidden. 

Sub-domains may expose, staging environments, web services, deprecated versions of the web app, admin portals, which may be buggy or
vulnerable to basic attacks or leak critical information.

### Enumerating Subdomains

There are two broad ways to approach enumerating subdomains:

+ Active Scanning
+ Passive Discovery

Passive techniques involve avoiding actively sending large volumes of requests to the webserver and instead utilise
techniques like OSINT and other forms of recon to discover publicly disclosed subdomain names. Techniques for active 
enumeration include:

+ Dictionary enumeration
+ Bruteforce 

Tools such as [sublist3r](https://github.com/aboul3la/Sublist3r) utilises OSINT specifically:

{{< md_html >}}
    <blockquote>
        "...search engines such as Google, Yahoo, Bing, Baidu and Ask. Sublist3r also enumerates subdomains using 
        Netcraft, Virustotal, ThreatCrowd, DNSdumpster and ReverseDNS."
    </blockquote>
{{< /md_html >}}

to passively discover subdomains listed on websites or crawled by search engines spiders.

Sublist3rs 'sister' tool [SubBrute](https://github.com/TheRook/subbrute) uses active techniques to discover subdomains. 
Running both forms of enumeration is a good idea.

### OSINT

Open Source Intelligence (OSINT) is a form of recon that aims to discover information useful to a tester /hacker 
which has been published in some way to the internet. That is the information is available openly to anyone that can
locate it. A classic example of OSINT uncovering useful information is discovering leaked credentials in GitHub
repositories.

A great resource for all things OSINT is [OSINT Framework](https://osintframework.com/).

### Quick Wins

Often times in the initial phases of testing a number of low findings or, 'quick wins' as I refer to them, will reveal
themselves to the tester. Some of these are:

+ Tokens in local storage
+ Pulling of http resources
+ Left over debugging messages

Keep an eye out for these as you browse manually through the site. 

#### TLS/SSL Certificates

Another great, and quick, check to perform is looking to see if the webserver will accept the usage of cryptographically
weak ciphersuites for client-server communication. The easiest way to do this is with [SSLScan](https://github.com/rbsec/sslscan).
Simply run:

`sslcan domain.name`

and look for any 128 bit ciphers that show as `ACCEPTED` by the webserver. Usage of these may count as a low finding.

### Code Review A.K.A Inspect element

At this stage I like to do a basic JavaScript code review. That is look at any JavaScript files that are loaded into 
the browser while browsing the web app. On occasion JS code can reveal things like:

+ Frontend validation / UI bypass'
+ Developer / Debugging comments
+ Interesting API endpoints
+ SQL statements
+ Hashing algorithms
+ Potential XSS vectors

Hence, it is always useful to spend a little time going through the code available to you on the frontend. Often times
JS code on the frontend is minified or obfuscated, it is important to get used to reading minified code, however Firefox
dev tools and indeed chrome dev-tools allow you to un-minify js code to some extent. Sites like [unminify](https://unminify.com/)
can also be handy here.

### Automated Scanners

Automated scanners are a classic trap and path to missing vulnerabilities. They do however have their place and can be 
useful as an assistive tool alongside manual testing. A good approach is to run automated scanners up-front while
you perform other manual tests.

### Summary

Getting a lay of the land is an exceptionally important part of effective testing. Knowing what there is to test and
what vulnerabilities could appear in those areas in critical to success and time saving. 

## The Mid Game

{{< md_html >}}
    <blockquote>
        "It's not about looking for everything everywhere, it's about looking where it ought to be found ..."
    </blockquote>
{{< /md_html >}}



The best chess players, and the algorithms that play chess, know to only analyse the relevant move set for a given
position, not every possible move. The same is true of web application pentesting, you can't test for everything, 
everywhere. You need to be able to distinguish when a particular vulnerability is relevant and know simple ways to
determine if a part of the application is likely to be vulnerable. 

### Build It

This process of knowing where to look is not one that can be learnt from following a guide or set of rules. All web 
applications manifest differently but often perform similar tasks. Knowing areas of developing a web application that
are likely to go wrong or can go wrong can only really come from two places:

+ Experience
+ DIY

The first is obtained over many tests, CTFs and writeups. It is earned through constantly learning as you go and is
incredibly valuable. 

The second is a different kind of experience. Build a social media clone. In the process you will discover endless headaches
and problems that need to be solved. In these moments you will look for a workaround or a solution and in most cases
you will take the first or easiest of these options. The same is true of professional developers. Time pushed and constantly
fighting to stay under budget means that developers look for the easiest and fastest solution to keep them moving forward. 
It is from solving these difficult or complex problems in this environment that leads to the introduction of security
flaws. Discovering these problems for yourself is invaluable.

There are many other benefits to this process as well:

+ Learning developer 'speak' will improve conversations with triage/patching
+ Understanding in depth how all the parts of a web application work together
+ Increased experience in web development trends

Ultimately nothing is better for your 'security eyes' then introducing the security vulnerabilities for yourself and 
understanding where and how they manifest.

### Summary

{{< md_html >}}
    <blockquote>
        "Finding vulnerabilities in web applications is about thinking where, as a developer, you would cut corners. That 
        is the problems that are the most annoying typically have the worst solutions."
    </blockquote>
{{< /md_html >}}

Look for vulnerabilities where they make sense not just for the sake of it.

## The End Game

{{< md_html >}}
    <blockquote>
        "When you see a good move, look for a better one" ― Emanuel Lasker
    </blockquote> 
{{< /md_html >}}

It is often tempting after a finding a vulnerability to go straight to writing and lodging the finding/report. Especially
whereas a tester you have invested a lot of time into the particular finding, or it is the first finding after a long
bout of testing. However, this is actually the best time to look for more vulnerabilities that complement the finding. That
is, can the finding be escalated?

This is an important habit to get into. Not only does vulnerability chaining improve bounty payouts, but it also increases
the risk rating of your finding. This is an important tool in persuasion and motivation to patch/remediate the finding
with urgency.

## Testing Checklist

By way of closure here is a checklist which summaries the approaches outlined in this post.

Coming soon ...

{{< md_html >}}
    <iframe src='https://svelte3-todo.surge.sh/'></iframe>
{{< /md_html >}}