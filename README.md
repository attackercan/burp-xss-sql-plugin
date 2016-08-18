# burp-xss-sql-plugin

Publishing plugin which I used for years which helped me to find several bugbounty-worthy XSSes, OpenRedirects and SQLi.  

__HTML Inj__: Special symbols are checked one-by-one if they appear in output. WAF/base64encoding/location/content-type/etc detections.  

__SQL Inj__: All parameters are transfered through SQLMap API to host, which in used for asynchronous scanning.  

__Tip__: Change Burp's Active Scan scope so it will automatically append new HTTP requests into queue, e.g.:

```
Host: bugbounty.com
File: (?<!js|jpg|jpeg|svg|css|ico|woff|cur|gif|png)$     // you don't want those extensions to be scanned  
```

SQLMap results can be extracted through API, e.g.:
```php
<?php

$f = file_get_contents("http://0.0.0.0:8775/admin/1/list");
$data = json_decode($f, true);
foreach($data as $tasks) {
	foreach($tasks as $id => $task) {
		$task_data = json_decode(file_get_contents("http://0.0.0.0:8775/scan/".$id."/data"), true);
		if(count($task_data['data']) > 0)
			echo "[".$id."] <h1>SQL Inj!</h1><br>";
		//else echo "[".$id."] None...<br>";
	}
}

?>
```
