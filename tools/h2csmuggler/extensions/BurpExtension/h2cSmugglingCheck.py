from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue


class BurpExtender(IBurpExtender, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("h2cSmuggler")
        callbacks.registerScannerCheck(self)
        self.urlLastScanned = None

    def doPassiveScan(self, baseRequestResponse):
        return None

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        request = baseRequestResponse.getRequest()
        requestInfo = self._helpers.analyzeRequest(baseRequestResponse)
        body = request[requestInfo.getBodyOffset():]

        # Avoid scanning the same endpoint for multiple insertion points
        if self.urlLastScanned == requestInfo.getUrl():
            return None
        self.urlLastScanned = requestInfo.getUrl()

        # More likely a false positive for cleartext connections
        confidence = "Certain"
        if baseRequestResponse.getHttpService().getProtocol != "https":
            confidence = "Tentative"

        # Replace headers in original request
        headers = requestInfo.getHeaders()
        newHeaders = []
        for header in headers:
            if header.startswith("Connection") or header.startswith("Upgrade"):
                pass
            else:
                newHeaders.append(header)
        newHeaders.append("Upgrade: h2c")
        newHeaders.append("HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA")

        # Build Requests
        connStr = "Connection: Upgrade, HTTP2-Settings"
        h2cRequestOne = self._helpers.buildHttpMessage(newHeaders + [connStr],
                                                       body)

        connStr = "Connection: Upgrade"
        h2cRequestTwo = self._helpers.buildHttpMessage(newHeaders + [connStr],
                                                       body)

        # Send Requests
        requestResponseOne = self._callbacks.makeHttpRequest(
                                baseRequestResponse.getHttpService(),
                                h2cRequestOne)
        requestResponseTwo = self._callbacks.makeHttpRequest(
                                baseRequestResponse.getHttpService(),
                                h2cRequestTwo)

        # Analyze responses
        responseOneInfo = self._helpers.analyzeResponse(
                                requestResponseOne.getResponse())
        responseTwoInfo = self._helpers.analyzeResponse(
                                requestResponseTwo.getResponse())

        ret = []
        if responseOneInfo.getStatusCode() == 101:
            ret.append(CustomScanIssue(
                baseRequestResponse.getHttpService(),
                requestInfo.getUrl(),
                [requestResponseOne],
                "HTTP/2 Cleartext (h2c) Upgrade Support Detected",
                """Server responded with 101 Switching Protocols. If this
                upgrade response is from a backend server behind a proxy, then
                intermediary proxy access controls (e.g., path and/or header
                restrictions) can be bypassed by using
                h2cSmuggler (https://github.com/BishopFox/h2csmuggler).""",
                confidence))

        if responseTwoInfo.getStatusCode() == 101:
            ret.append(CustomScanIssue(
                baseRequestResponse.getHttpService(),
                requestInfo.getUrl(),
                [requestResponseTwo],
                """"HTTP/2 Cleartext (h2c) Upgrade Support Detected",
                Server responded with 101 Switching Protocols. If this
                upgrade response is from a backend server behind a proxy, then
                intermediary proxy access controls (e.g., path and/or header
                restrictions) can be bypassed by using
                h2cSmuggler (https://github.com/BishopFox/h2csmuggler).
                <br><br> This instance did not require a Connection header to
                forward the HTTP2-Settings header.
                (use h2cSmuggler's --upgrade-only option)""",
                confidence))

        if len(ret) == 0:
            return None

        return ret

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getUrl() == newIssue.getUrl():
            return -1

        return 0


class CustomScanIssue (IScanIssue):

    def __init__(self, httpService, url, httpMessages, name, detail,
                 confidence):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._confidence = confidence

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return "High"

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
