#### What is information disclosure?

Information disclosure, also known as information leakage, is when a website unintentionally reveals sensitive information to its users. Depending on the context, websites may leak all kinds of information to a potential attacker, including:

- Data about other users, such as usernames or financial information
- Sensitive commercial or business data
- Technical details about the website and its infrastructure

The dangers of leaking sensitive user or business data are fairly obvious, but disclosing technical information can sometimes be just as serious. Although some of this information will be of limited use, it can potentially be a starting point for exposing an additional attack surface, which may contain other interesting vulnerabilities. The knowledge that you are able to gather could even provide the missing piece of the puzzle when trying to construct complex, high-severity attacks.

Occasionally, sensitive information might be carelessly leaked to users who are simply browsing the website in a normal fashion. More commonly, however, an attacker needs to elicit the information disclosure by interacting with the website in unexpected or malicious ways. They will then carefully study the website's responses to try and identify interesting behavior.

### Examples of information disclosure

Some basic examples of information disclosure are as follows:

- Revealing the names of hidden directories, their structure, and their contents via a `robots.txt` file or directory listing
- Providing access to source code files via temporary backups
- Explicitly mentioning database table or column names in error messages
- Unnecessarily exposing highly sensitive information, such as credit card details
- Hard-coding API keys, IP addresses, database credentials, and so on in the source code
- Hinting at the existence or absence of resources, usernames, and so on via subtle differences in application behavior


#### How do information disclosure vulnerabilities arise?

Information disclosure vulnerabilities can arise in countless different ways, but these can broadly be categorized as follows:

- **Failure to remove internal content from public content**. For example, developer comments in markup are sometimes visible to users in the production environment.
- **Insecure configuration of the website and related technologies**. For example, failing to disable debugging and diagnostic features can sometimes provide attackers with useful tools to help them obtain sensitive information. Default configurations can also leave websites vulnerable, for example, by displaying overly verbose error messages.
- **Flawed design and behavior of the application**. For example, if a website returns distinct responses when different error states occur, this can also allow attackers to , such as valid user credentials.

Information disclosure vulnerabilities can have both a direct and indirect impact depending on the purpose of the website and, therefore, what information an attacker is able to obtain. In some cases, the act of disclosing sensitive information alone can have a high impact on the affected parties. For example, an online shop leaking its customers' credit card details is likely to have severe consequences.

On the other hand, leaking technical information, such as the directory structure or which third-party frameworks are being used, may have little to no direct impact. However, in the wrong hands, this could be the key information required to construct any number of other exploits. The severity in this case depends on what the attacker is able to do with this information.


#### How to test for information disclosure vulnerabilities

Generally speaking, it is important not to develop "tunnel vision" during testing. In other words, you should avoid focussing too narrowly on a particular vulnerability. Sensitive data can be leaked in all kinds of places, so it is important not to miss anything that could be useful later. You will often find sensitive data while testing for something else. A key skill is being able to recognize interesting information whenever and wherever you do come across it.

The following are some examples of high-level techniques and tools that you can use to help identify information disclosure vulnerabilities during testing.


    Fuzzing
    Using Burp Scanner
    Using Burp's engagement tools
    Engineering informative responses


LAB1 : 
- With Burp running, open one of the product pages.
- In Burp, go to "Proxy" > "HTTP history" and notice that the `GET` request for product pages contains a `productID` parameter. Send the `GET /product?productId=1` request to Burp Repeater. Note that your `productId` might be different depending on which product page you loaded.
- In Burp Repeater, change the value of the `productId` parameter to a non-integer data type, such as a string. Send the request:
    
    `GET /product?productId="example"`
- The unexpected data type causes an exception, and a full stack trace is displayed in the response.

LAB2 : 
- With Burp running, browse to the home page.
- Go to the "Target" > "Site Map" tab. Right-click on the top-level entry for the lab and select "Engagement tools" > "Find comments". Notice that the home page contains an HTML comment that contains a link called "Debug". This points to `/cgi-bin/phpinfo.php`.
- In the site map, right-click on the entry for `/cgi-bin/phpinfo.php` and select "Send to Repeater".
- In Burp Repeater, send the request to retrieve the file. Notice that it reveals various debugging information, including the `SECRET_KEY` environment variable.


#### User account pages

By their very nature, a user's profile or account page usually contains sensitive information, such as the user's email address, phone number, API key, and so on. As users normally only have access to their own account page, this does not represent a vulnerability in itself. However, some websites contain logic flaws that potentially allow an attacker to leverage these pages in order to view other users' data.

```http
GET /user/personal-info?user=carlos
```

Most websites will take steps to prevent an attacker from simply changing this parameter to access arbitrary users' account pages. However, sometimes the logic for loading individual items of data is not as robust.

An attacker may not be able to load another users' account page entirely, but the logic for fetching and rendering the user's registered email address, for example, might not check that the `user` parameter matches the user that is currently logged in. In this case, simply changing the `user` parameter would allow an attacker to display arbitrary users' email addresses on their own account page.

#### Source code disclosure via backup files

Obtaining source code access makes it much easier for an attacker to understand the application's behavior and construct high-severity attacks. Sensitive data is sometimes even hard-coded within the source code. Typical examples of this include API keys and credentials for accessing back-end components.

If you can identify that a particular open-source technology is being used, this provides easy access to a limited amount of source code.

Occasionally, it is even possible to cause the website to expose its own source code. When mapping out a website, you might find that some source code files are referenced explicitly. Unfortunately, requesting them does not usually reveal the code itself. When a server handles files with a particular extension, such as `.php`, it will typically execute the code, rather than simply sending it to the client as text. However, in some situations, you can trick a website into returning the contents of the file instead. For example, text editors often generate temporary backup files while the original file is being edited. These temporary files are usually indicated in some way, such as by appending a tilde (`~`) to the filename or adding a different file extension. Requesting a code file using a backup file extension can sometimes allow you to read the contents of the file in the response.

LAB3: 
- Browse to `/robots.txt` and notice that it reveals the existence of a `/backup` directory. Browse to `/backup` to find the file `ProductTemplate.java.bak`. Alternatively, right-click on the lab in the site map and go to "Engagement tools" > "Discover content". Then, launch a content discovery session to discover the `/backup` directory and its contents.
- Browse to `/backup/ProductTemplate.java.bak` to access the source code.

##### Information disclosure due to insecure configuration

Websites are sometimes vulnerable as a result of improper configuration. This is especially common due to the widespread use of third-party technologies, whose vast array of configuration options are not necessarily well-understood by those implementing them.

In other cases, developers might forget to disable various debugging options in the production environment. For example, the HTTP `TRACE` method is designed for diagnostic purposes. If enabled, the web server will respond to requests that use the `TRACE` method by echoing in the response the exact request that was received. This behavior is often harmless, but occasionally leads to information disclosure, such as the name of internal authentication headers that may be appended to requests by reverse proxies.


LAB4 : 
- In Burp Repeater, browse to `GET /admin`. The response discloses that the admin panel is only accessible if logged in as an administrator, or if requested from a local IP.
- Send the request again, but this time use the `TRACE` method:
    
    `TRACE /admin`
- Study the response. Notice that the `X-Custom-IP-Authorization` header, containing your IP address, was automatically appended to your request. This is used to determine whether or not the request came from the `localhost` IP address.
- Go to "Proxy" > "Options", scroll down to the "Match and Replace" section, and click "Add". Leave the match condition blank, but in the "Replace" field, enter:
    
    `X-Custom-IP-Authorization: 127.0.0.1`
    
    Burp Proxy will now add this header to every request you send.

***The HTTP `TRACE` method performs a message loop-back test along the path to the target resource, providing a useful debugging mechanism.***

##### Version control history

Virtually all websites are developed using some form of version control system, such as Git. By default, a Git project stores all of its version control data in a folder called `.git`. Occasionally, websites expose this directory in the production environment. In this case, you might be able to access it by simply browsing to `/.git`.

While it is often impractical to manually browse the raw file structure and contents, there are various methods for downloading the entire `.git` directory. You can then open it using your local installation of Git to gain access to the website's version control history. This may include logs containing committed changes and other interesting information.

This might not give you access to the full source code, but comparing the diff will allow you to read small snippets of code. As with any source code, you might also find sensitive data hard-coded within some of the changed lines.

LAB5: 
- Open the lab and browse to `/.git` to reveal the lab's Git version control data.
- Download a copy of this entire directory. For Linux users, the easiest way to do this is using the command:
    
    `wget -r https://YOUR-LAB-ID.web-security-academy.net/.git/`
    
    Windows users will need to find an alternative method, or install a UNIX-like environment, such as Cygwin, in order to use this command.
    
- Explore the downloaded directory using your local Git installation. Notice that there is a commit with the message `"Remove admin password from config"`.

-r,  --recursive                 specify recursive download