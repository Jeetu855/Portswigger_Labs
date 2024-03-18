
### Battling Parasoft DTP :: Default Creds to RCE

Original Writeup Link : \https://xboy.me/post/CORP-RCE

Lets call the program xboy.me and in scope is \*xboy.me 
First do shodan dork 
```
ssl:"*.xboy.me"
```

Use this when you want to find low hanging and easily to find bugs, like open admin panels or any internal panels on weird (non-conventional) ports.

Found 
\https://dtp.xboy.me:8443/tcm/welcome.jsp?redirectUrl=https%3A%2F%2Fdtp.xboy.me%3A8443%2Ftcm%2Findex.html

Parasoft Development Testing Platform (DTP) : Default Creds = admin:admin worked

---

Link to Original Writeup : \https://medium.com/@hacdoc/how-i-get-my-first-bounty-ec4d83eb5fbf

Github Dorking
```
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