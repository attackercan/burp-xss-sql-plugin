from burp import IBurpExtender, IScanIssue, IScannerCheck, IHttpListener, IProxyListener, IScannerListener, IExtensionStateListener
from java.io import PrintWriter
from java.lang import RuntimeException
from uuid import uuid4
import urllib2
import array
import re
import json
import hashlib
import os.path
import string
import random

class BurpExtender(IBurpExtender, IScannerCheck, IHttpListener, IProxyListener, IScannerListener, IExtensionStateListener):

    def registerExtenderCallbacks(self, callbacks):

        global burp_callbacks
        burp_callbacks = callbacks
        global burp_helpers
        burp_helpers = burp_callbacks.getHelpers()
        burp_callbacks.setExtensionName("BugBountyPlugin")
        
        self.stdout = PrintWriter(burp_callbacks.getStdout(), True)
        
        self.println("SQL/XSS custom plugin (c) @httpsonly")
        
        burp_callbacks.registerScannerCheck(self)
        burp_callbacks.registerProxyListener(self)
        return

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        textIssue = ""
        tags = ""
        doSqlmap = 1
        name = insertionPoint.getInsertionPointName()
        value = insertionPoint.getBaseValue()
        if re.search(r'^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{4})$', value) is not None:
        	doSqlmap = 0
        	#textIssue = "<i>Input parameter '"+name+"' is Base64-encoded</i><br>"
        if re.search(r'(?i)(.*?)http[s]*:\/\/(.*?)', value) is not None:
        	doSqlmap = 0
        	textIssue = "<i>Input parameter '"+name+"' has http(s)://</i><br>"
        if re.search(r'(?i)(.*?)<\?xml(.*?)', value) is not None:
        	doSqlmap = 0
        	textIssue = textIssue + "<i>Input parameter '"+name+"' has &lt;?xml</i><br>"
        if doSqlmap == 1:
        	#sqlmap_host = '10.0.70.51'
        	sqlmap_host = 'mydomain.com'
        	reqHeaders = burp_helpers.bytesToString(baseRequestResponse.getRequest())
        	referer = None
        	cookie = None
        	postdata = None
        	reqInfo = burp_helpers.analyzeRequest(baseRequestResponse)
        	url = str(reqInfo.getUrl())
        	if re.search(r'(?i)Cookie: (.*?)[\r|\n]', reqHeaders) is not None:
        		cookie = re.search(r'(?i)Cookie: (.*?)[\r|\n]', reqHeaders).group(1)
        	if re.search(r'[\r|\n]{2}(.*?)$', reqHeaders) is not None:
        		postdata = re.search(r'[\r|\n]{2}(.*?)$', reqHeaders).group(1)
        	#SQLMap API
        	try:
        		req = urllib2.Request('http://'+sqlmap_host+':8775/task/new')
        		resp = json.load(urllib2.urlopen(req))
        		if resp['success'] == True and resp['taskid']:
        			sqlitask = resp['taskid']
        			sqliopts = {'delay': 0, 'risk': 1, 'timeout': 30, 'level': 1, 'answers': 'crack=N,dict=N', 'cookie': cookie, 'threads': 1, 'url': url, 'referer': referer, 'retries': 3, 'timeSec': 5, 'getBanner': True, 'data': postdata, 'timeSec': 5}
        			try:
        				req = urllib2.Request('http://'+sqlmap_host+':8775/option/' + sqlitask + '/set')
        				req.add_header('Content-Type', 'application/json')
        				resp = json.load(urllib2.urlopen(req, json.dumps(sqliopts)))
        				if resp['success'] == True:
        					sqliopts = {'url': url}
        					try:
        						checkreq = urllib2.Request('http://'+sqlmap_host+':8775/option/' + sqlitask + '/list')
        						checkresp = json.load(urllib2.urlopen(checkreq))
        					except:
        						print 'Failed to get list of options from SQLMap API\n'
        					try:
        						req = urllib2.Request('http://'+sqlmap_host+':8775/scan/' + sqlitask + '/start')
        						req.add_header('Content-Type', 'application/json')
        						resp = json.load(urllib2.urlopen(req, json.dumps(sqliopts)))
        						if resp['success'] == True:
        							print 'Started SQLMap Scan on Task ' + sqlitask +'\n'
        						else:
        							print 'Failed to start SQLMap Scan for Task: ' + sqlitask + '\n'
        					except:
        						print 'Failed to start SQLMap Scan for Task: ' + sqlitask + '\n'
        				else:
        					print 'Failed to set options on SQLMap Task: ' + sqlitask + '\n'
        			except:
        				print 'Failed to set options on SQLMap Task: ' + sqlitask + '\n'
        		else:
        			print 'SQLMap task creation failed\n'
        	except:
        		print 'SQLMap task creation failed\n'
        score = 0
        flag1 = 0
        attack1 = burp_callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), insertionPoint.buildRequest(burp_helpers.stringToBytes("yyyyyyyyy")))
        response1 = attack1.getResponse()
        response_str1 = burp_helpers.bytesToString(response1)
        # if re.search(r'[\r|\n](?i)(Content-type:[\s]*application\/(?!xml)(.*?))[\r|\n]', response_str1) is not None:
        	# return None
        	# break
        #m = re.search(r'<([a-zA-Z0-9]+)[^>]*([^<]*?)yyyyyyyyy', response_str1)
        # if m.group(1) is not None:
        	# textIssue = textIssue + "Input parameter gets into tag '"+m.group(1)+"'<br>"
        	# flag1 = 1
        	# if m.group(1) == 'script': score = 4
        if re.search(r'(?is)(<script(.*)yyyyyyyyy(.*)<\/script)', response_str1) is not None:
       		score = 4
        result = re.findall(r'[\s"\'`;\/0-9\=]+on\w+\s*=[^>]*yyyyyyyyy(.*?)>', response_str1)
        if result:
        	textIssue = textIssue + "Input parameter gets into on* - header<br>"
        	flag1 = 1
        	# score = 4
        if re.search(r'[\r|\n](?i)Location:(.*?)yyyyyyyyy(.*?)[\r|\n]', response_str1) is not None:
        	textIssue = textIssue+"Location: header injection<br>"
        	flag1 = 1
        payload_array = ["'\"", "<", ">", "\\\\'ttt", "\\\\\"ggg", "\\"]
        payload_all = ""
        rand_str = "jjjjjjj"
        for payload in payload_array:
        	payload_all = payload_all+rand_str+payload
        #payload_all = payload_all+rand_str
        payload_bytes = burp_helpers.stringToBytes(payload_all)
        attack = burp_callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), insertionPoint.buildRequest(payload_bytes))
        response = attack.getResponse()
        response_str = burp_helpers.bytesToString(response)
        if_found_payload = ""
        non_encoded_symbols = ""
        severity = "Low"
        for check_payload in payload_array:
			if_found_payload = rand_str+check_payload
			if if_found_payload in response_str:
				non_encoded_symbols = non_encoded_symbols+"   "+check_payload.replace('<', '&lt;')
				score = score+1
				flag1 = 1
        if score > 2: severity = "Medium"
        if score > 3: severity = "High"
        if non_encoded_symbols == "   \\\\'ttt":
        	severity = "Information"
        if non_encoded_symbols != '':
			textIssue = textIssue + "<br><br>Symbols not encoded: "+non_encoded_symbols+"<br>"
        if 'jjjjjjj' not in response_str and flag1 == 1:
			textIssue = textIssue + '<br><h3>WAF deleted payload string with symbols! Please bypass</h3>'
        if flag1 == 1:
        	return [CustomScanIssue(burp_helpers.analyzeRequest(attack).getUrl(), "BugBounty Plugin", 134217728, severity, "Certain", None, None, textIssue, None, [attack], attack.getHttpService())]


    def doPassiveScan(self, baseRequestResponse):
        pass

    def println(self, message):
        self.stdout.println(message)

    def randstring(n):
		a = string.ascii_letters + string.digits
		return ''.join([random.choice(a) for i in range(n)])


class CustomScanIssue(IScanIssue):
    def __init__(self, Url, IssueName, IssueType, Severity, Confidence, IssueBackground,
                 RemediationBackground, IssueDetail, RemediationDetail, HttpMessages, HttpService):
        self._Url = Url
        self._IssueName = IssueName
        self._IssueType = IssueType
        self._Severity = Severity
        self._Confidence = Confidence
        self._IssueBackground = IssueBackground
        self._RemediationBackground = RemediationBackground
        self._IssueDetail = IssueDetail
        self._RemediationDetail = RemediationDetail
        self._HttpMessages = HttpMessages
        self._HttpService = HttpService

    def getUrl(self):
        return self._Url

    def getIssueName(self):
        return self._IssueName

    def getIssueType(self):
        return self._IssueType

    def getSeverity(self):
        return self._Severity

    def getConfidence(self):
        return self._Confidence

    def getIssueBackground(self):
        return self._IssueBackground

    def getRemediationBackground(self):
        return self._RemediationBackground

    def getIssueDetail(self):
        return self._IssueDetail

    def getRemediationDetail(self):
        return self._RemediationDetail

    def getHttpMessages(self):
        return self._HttpMessages

    def getHttpService(self):
        return self._HttpService


