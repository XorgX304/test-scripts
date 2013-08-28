#!/usr/bin/python2
import requests # import vanilla requests
import requesocks # import requesocks

checkIP = "http://ifconfig.me/ip" # IP check site

def getip_requests(checkIP):
    print "(+) Sending request with plain ole requests..."
    r = requests.get(checkIP)
    print "(+) IP is: " + r.text.replace("\n", "")

def getip_requesocks(checkIP):
    print "(+) Sending request with requesocks..."
    session = requesocks.session()
    session.proxies = {'http': 'socks5://127.0.0.1:9050',
                       'https': 'socks5://127.0.0.1:9050'}
    r = session.get(checkIP)
    print "(+) IP is: " + r.text.replace("\n", "")

def main():
    print "Running tests..."
    getip_requests(checkIP)
    getip_requesocks(checkIP)

if __name__ == "__main__":
    main()
