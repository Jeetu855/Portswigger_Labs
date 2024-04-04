
```
inurl:responsible disclosure       filter by most recent to check new launch or recent updates

```

Asset Type : Wildcard , VDP

```
inurl:tesla.com ext:php
```


The **Common Weakness Enumeration** (CWE) is a category system for hardware and software weaknesses and vulnerabilities. It is sustained by a community project with the goals of understanding flaws in software and hardware and creating automated tools that can be used to identify, fix, and prevent those flaws

The Common Vulnerabilities and Exposures (CVE) system provides a reference method for publicly known information-security vulnerabilities and exposures
`CVE-YEAR-IDNUMBER`

crt.sh **provides a searchable database of certificate transparency logs**.

Passive Subdomain Enum : 

\https://chaos.projectdiscovery.io/#/
to find subdomains

Subfinder for passive subdomain enum. 

Subfinder usage
-d : to provide domain

```
subfinder -d tesla.com
```

To provide a list of domains havinf wildcards

```sh
subfinder -dL wildcardDomainList.txt
```

Remove the \* from wildcard domains, just add the domain name

-all :                           use all sources for enumeration (slow)
-o : output to a file

```sh
subfinder -d tesla.com -all
```

```sh
subdinder -d tesla.com -recursive
```

Difference between -all and -recursive

5 different flags for subfiner
Find a good target

The function of `-all` the flag is to use all sources (crtsh, Common Crawl, Wayback Archive, etc.) when doing subdomain enumeration. If you use the basic command, then only a few sources are used.

--exclude-sources: This option allows us to exclude specific data sources from the enumeration process. For example, if we don't want to include results from Shodan, you can use the following command:

```sh
subfinder -d example.com --exclude-sources shodan
```

--no-passive: This option disables passive subdomain enumeration. This means that subfinder will only use active methods to enumerate subdomains, such as DNS resolution and HTTP requests. You can use the following command:

```sh
subfinder -d example.com --no-passive
```


--exclude-subdomains: This option allows you to exclude specific subdomains from the results. For example, if you want to exclude all subdomains that contain the string "test", you can use the following command:

```sh
subfinder -d example.com --exclude-subdomains "*test*"
```


-v or --verbose: Enable verbose output, which displays more information about the enumeration process.

-r or --recursive: Enable recursive subdomain enumeration. This option enables subfinder to search for subdomains of the subdomains it finds.


---

SOCMINT : Social Media Intelligence

\https://osintframework.com/
\https://dnsdumpster.com/


---

cpanel

crt.sh   :  certificate check
bgp.he.net  :  ANS numbers

```sh
amass enum -passive -d test.com
```

```sh
amass enum -active -d test.com
```

Probe, rate limit, output

httpx

- -sc ,-status-code : to display status codes
- -cl ,-content-length: t0 display content length
- -title : display page title
- -bp, -body-preview    display first N characters of response body (default 100)
- -server, -web-server  display server name
- -td, -tech-detect     display technology in use based on wappalyzer dataset (default true)
- -path: a specified path to check if it exists or not
```sh
httpx -l list -path /robots.txt
```
- -mc, -match-code string            match response with specified status code (-mc 200,302)
- -ml, -match-length string          match response with specified content length (-ml 100,102)
- -mlc, -match-line-count string     match response body with specified line count (-mlc 423,532)
- -mwc, -match-word-count string     match response body with specified word count (-mwc 43,55)
-    -ms, -match-string string          match response with specified string (-ms admin)
-  -mr, -match-regex string           match response with specified regex (-mr admin)
- -fc, -filter-code string            filter response with specified status code (-fc 403,401)
- -fl, -filter-length string          filter response with specified content length (-fl 23,33)
-  -flc, -filter-line-count string     filter response body with specified line count (-flc 423,532)
-   -fwc, -filter-word-count string     filter response body with specified word count (-fwc 423,532)
-    -t, -threads int              number of threads to use (default 50)
-    -rl, -rate-limit int          maximum requests to send per second (default 150)
-  -rlm, -rate-limit-minute (int)  maximum number of requests to send per minute
- -o, -output string                  file to write output results
- -oa, -output-all                    filename to write output results in all formats
- -j, -json                           store output in JSONL(ines) format
- -ip                   display host ip
- -cdn                  display cdn/waf in use (default true)
- -debug: it shows requests and responses to a webpage in CLI

---

Cookies, Local Storage, Session Storage : All 3 of them stoed on users browser
Cookies Stored in browser+ Server
Cookies Expiration is manually set during its creation
Local Strage data never expires 
Session Storage expires on tab close
Only cookies sent woth each request
Cookies size small upto  4kb meanwhile local and session storage is 10mb and 5mb respectively

During login, we exchange our username and password for session Id which is soted in a cookie
For subsequesnt requests sent by the browsers, cookie containing session ID is sent with each request and username and password re no longer required
Cookie is a medium to transport session ID 
Session ID randomly generated value
Cookies can be modified by client and so servers store cookies as well

---

Nuclei : template based scanner
best for cve hunting

Run DELETE  on meeting request
Nuclei usage
How to run unsigned templates
Naabu usage

```sh
naabu -host example.com
```

`-p` : set the port that should be scanned

```sh
naabu -host example.com -port 80
```

`-c` : general internal worker threads (default 25)

```sh
naabu -host example.com -c 10
```

`-rate` : packets to send per second (default 1000)

```sh
naabu -host example.com -rate 25
```

`-top-ports, -tp string`      top ports to scan (default 100) (full,100,1000)

```sh
naabu -host example.com -top-ports 200
```

`-list, -l string`            list of hosts to scan ports (file)

```sh
naabu -list example.txt -port 80,443
```

nuclei uses httpx again even after we have used again so we use `-nh`
`nh, -no-httpx`                   disable httpx probing for non-url input

AEM : Adobe Experience manager: lookout for this

```sh
nuclei -target example -t ~/nuclei_templates -tags panel, aem, adobe -es info -ept dns,tcp,ssl -markdown-export /nuclei_reports/nameOfReport
```

Run all the nuclei templates that contain these tags in their yaml file

```shodan
http.title:"aem sign in"
```

Get output in md

```sh
nuclei -target 10.10.181.110:8080 -t ~/nuclei-templates -tags apache
```

Output
```sh
[CVE-2021-41773:LFI] [http] [high] http://10.10.181.110:8080/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd
[apache-detect] [http] [info] http://10.10.181.110:8080 [Apache/2.4.49 (Unix)]
```


```sh
nuclei -target 10.10.181.110:8080 -t ~/nuclei-templates -tags apache -es info
```

Output

```sh
[INF] Running httpx on input host
[INF] Found 1 URL from httpx
[INF] Templates clustered: 6 (Reduced 4 Requests)
[INF] Using Interactsh Server: oast.online
[CVE-2021-41773:LFI] [http] [high] http://10.10.181.110:8080/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd
```

This time it excludes the informational data, also we can see it runs httpx by default which we can stop using the tag `-no-httpx`

```sh
nuclei -target 10.10.181.110:8081 -t ~/nuclei-templates -tags apache
```

![[Pasted image 20240329174029.png]]

```sh
nuclei -target 10.10.181.110:8081 -t ~/nuclei-templates -tags apache -es info
```

![[Pasted image 20240329175302.png]]

```sh
nuclei -target 10.10.181.110:8081 -t ~/nuclei-templates -tags apache,cve,traveral,rce,lfi,cve2021 -es info
```

![[Pasted image 20240329175615.png]]

***Tags that we give are OR condition not AND since when we include more Tags we can see more number of templates being clustered for request and also it takes more time to complete the scan***

```sh
nuclei -target 10.10.255.110:8090 -t ~/nuclei-templates -tags confluence,cve,auth-bypass -es info -ept dns,tcp,ssl -markdown-export ~/nuclei_reports/
```

Output

![[Pasted image 20240329194310.png]]

```sh
nuclei -target 10.10.255.110:8090 -t ~/nuclei-templates -tags confluence -es info -ept dns,tcp,ssl -markdown-export ~/nuclei_reports/
```

Output

![[Pasted image 20240329194207.png]]

---

Reconftw
Read about vulns in payloads all the things

auto calibrate

---

CMS for hosting and server for hosting
1. **CMS (Content Management System):**
    
    - A CMS is a software application or platform that enables users to create, manage, and modify digital content on a website without the need for specialized technical knowledge.
    - Examples of popular CMS platforms include WordPress, Joomla, Drupal, and Shopify (for e-commerce).
    - CMS platforms typically provide features such as content creation and editing, user management, themes/templates, plugins/extensions for additional functionality, and often include built-in SEO tools.
    - Users interact with the CMS through a web-based interface, allowing them to add new pages, update existing content, manage media files, and more.
2. **Server for Hosting:**
    
    - A server for hosting refers to the hardware and software infrastructure that stores and serves website content to users over the internet.
    - This infrastructure typically consists of physical or virtual servers running web server software (e.g., Apache, Nginx) and other necessary components (such as databases, scripting languages, etc.).
    - The server hosts the files and databases that make up the website, and it processes requests from users' web browsers to serve the appropriate content.
    - Hosting providers offer various types of hosting services, including shared hosting, virtual private servers (VPS), dedicated servers, cloud hosting, etc., each offering different levels of performance, scalability, and control.

In summary, a CMS is a software application used to manage website content, while a server for hosting refers to the infrastructure that stores and serves the website files and databases to users. They are complementary components of a website hosting environment, with the CMS providing the tools for content management, and the server hosting the website files and serving them to visitors.

assetnote wordlists
wordlists.assetnote.io
assetnote.io for blogs
trufflehog

shushiwushi : for  google dorks for finding private BB programs
Load config in burp : sets in scopes

---

RCE vs Command Injection

When we get shell is RCE
Path traversal leading to information disclosure
Info disclosure : api keys , user info PII leak, source code, 
JWT : Header Signture Payload

---

Web sites have photos videos of other sources and there might be tracking cookies so those things fill up our proxy

site map -> right click -> add to scope 
same thing in proxy  -> left click on filter settings and select -> show only in scope options

to also get subdomains -> scope -> edit -> checkbox Include Subdomains