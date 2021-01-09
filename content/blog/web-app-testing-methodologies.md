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
and expose services which may be vulnerable to simple attacks or CVES. A trusty nmap command string,   

`nmap -sC -sV -OA <target-ip> -p- >> <save file>`

is often more than enough to uncover a great deal of useful information about the kinds of services hanging off the
web application backend. 



< ? anlogy for subdomains >

< OSINT >

< Easy low findings and cheap wins >
    < certs, local storage >

### Code Review

### Automated Scanners
< notes on automated scanners >

## The Mid Game

< timely analysis >

The best chess players and the algorithms that play AI chess know to only analyse the relevant move set for a given
position, not every possible move. The same is true of web application pentesting, you can't test for everything, 
everywhere. You need to be able to distinguish when a particular vulnerability is relevant and know simple ways to
determine if a part of the application is likely to be vulnerable. 

<  >


## The End Game

< exploitation >

< chaining & escalation >
