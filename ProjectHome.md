![http://securitytheatre.files.wordpress.com/2012/09/manipulator.jpg](http://securitytheatre.files.wordpress.com/2012/09/manipulator.jpg)

# What is The Manipulator? #

The Manipulator is a command line scanner that can be used to identify parameter manipulation vulnerabilities, also known as [Insecure Direct Object References](https://www.owasp.org/index.php/Top_10_2010-A4-Insecure_Direct_Object_References) or [Authorization Bypass Through User-Controlled Key](http://cwe.mitre.org/data/definitions/639.html). The Manipulator parses [Burp](http://www.portswigger.net/) logs searching for numeric parameters which it analyses for parameter manipulation flaws by submitting a range of similar but different numeric values and looking for differences in the responses. It can also parse a second burp log (i.e. from a different user) to identify potentially user-specific parameter values.

The Manipulator is beta; don't use it in an environment that matters to you or anyone else. Do not use The Manipulator to scan hosts without the owner's permission.

# Features #
  * Support for automated detection and testing of numeric parameters in a range of locations including:
    * GET query strings
    * POST URI
    * POST body
    * Multipart forms
  * Multi-burplog mode, where parameter values are sourced from a different burp log
  * Scan 'state' maintenance:
    * Halt a scan at any time - scan progress is saved and you can easily resume a scan from the URL where you stopped
    * Specify a specific request number to resume a scan from
  * HTML format output with:
    * links/buttons to send Proof of Concept requests

# What do I need to use The Manipulator? #

The Manipulator is built and tested on [BackTrack 5 R2](http://www.backtrack-linux.org/). On all other platforms Your Mileage May Vary; you will need a an OS that can support bash (`*`nix, cygwin (not tested), etc), curl must be installed and in your path, and 'replace' (which is missing from many nix's) must also be installed in in your path. Until I implement web spider functionality, The Manipulator is dependent upon [burp proxy](http://portswigger.net) to create log files (not burp state files) which The Manipulator uses to build its internal list of fuzz requests. The free version of burp can be used to create these log files. Within Burp go to options > misc and check the proxy requests tick box; browse the target site, populate your log, then pass it to The Manipulator.

# How does The Manipulator work? #

The Manipulator receives a burp log (which you must create for it) that specifies a bunch of HTTP requests. Requests in the burp log look like this:

```
======================================================
3:09:54 PM  http://192.168.182.136:80
======================================================
POST /orangehrm/menu.php?TEST=1111 HTTP/1.1
Host: 192.168.182.136
Accept: */*
Accept-Language: en
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)
Connection: close
Referer: http://192.168.182.136/orangehrm/index.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 62
Cookie: PHPSESSID=bf7u0ad95cbubpcvdjda2bqro3; Loggedin=True; EliteNinja=False

module=Home&action=UnifiedSearch&search_form=false&tabnumber=1
======================================================
```

The Manipulator converts these into it's own format; a list of all the requests like this:

```
GET /orangehrm/menu.php?TEST=1111
POST /orangehrm/menu.php?TEST=1111??module=Home&action=UnifiedSearch&search_form=false&tabnumber=1
GET /orangehrm/index.php?module=Contacts&action=index&return_module=Contacts&return_action=DetailView&&print=true
GET /orangehrm/index.php?module=Home&menu_no=0&menu_no_top=home&submenutop=home1 
```

The list of requests are passed into the main scanning loop, which looks at each parameter value of each request; if it finds a numeric value, it generates a list of values that are a little greater and a little smaller than the current value. Then it sends a normal 'reference' request, followed by requests with the generated numeric values. Finally, the responses are diffed in order to identify a potential vulnerability.

# Why was The Manipulator created? #

I've found a few devastating parameter manipulation bugs over the years; I'd like to find more. I don't know of any other scanners that can find parameter manipulation bugs, and I have a basic fuzzing engine within [sqlifuzzer](http://code.google.com/p/sqlifuzzer/); The Manipulator is a modified version of sqlifuzzer, dedicated to parameter manipulation testing.

# Thanks #

People I stole/learned from:

  * The curl team - http://curl.haxx.se/
  * Brian Holyfield - I stole a load of ideas from a tool written by Brian
  * [PortSwigger](http://portswigger.net/burp/proxy.html) - Creator of Burp Suite
  * Toby Shelswell for multi-burplog concept

# Also... #

If you like The Manipulator, check out:

[sqlifuzzer](http://code.google.com/p/sqlifuzzer/)

[MIMeGusta](http://code.google.com/p/mimegusta/)