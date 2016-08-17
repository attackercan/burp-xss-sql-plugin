# burp-xss-sql-plugin

Publishing plugin which I used for years which helped me to find several bugbounty-worthy XSSes, OpenRedirects and SQLi.  

__HTML Inj__: Special symbols are checked one-by-one if they appear in output. WAF/base64encoding/location/content-type/etc detections.  

__SQL Inj__: All parameters are transfered through SQLMap API to host, which in used for asynchronous scanning.  

__Tip__: Change Burp's Active Scan scope so it will automatically append new HTTP requests into queue, e.g.:

```
Host: bugbounty.com
File: (?<!js|jpg|jpeg|svg|css|ico|woff|cur|gif|png)$     // you don't want those extensions to be scanned  
```
