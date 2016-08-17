# burp-xss-sql-plugin

Publishing plugin which I used for years which helped me to find several bugbounty-worthy XSSes, OpenRedirects and SQLi.  

`HTML Inj`: Special symbols are checked one-by-one if they appear in output. WAF/base64encoding/location/content-type/etc detections.  

`SQL Inj`: All parameters are transfered through SQLMap API to host, which in used for asynchronous scanning.  
