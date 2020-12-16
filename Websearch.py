import socket
import pyfiglet
import os
import requests
import threading

# os.system('cls')  # clear Shell
os.system('clear')

banner = pyfiglet.figlet_format("WebSEARCH")
print(banner)

remoteServer = input("Enter a remote host or IP to scan: ")
http = 'http://'
req1 = http + remoteServer
https = 'https://'
req2 = https + remoteServer

print("-" * 50)

def ipv4addr(remoteServer):  # Check IPv4
    try:
        socket.inet_pton(socket.AF_INET, remoteServer)
    except AttributeError:
        try:
            socket.inet_aton(remoteServer)
        except socket.error:
            return False
    except socket.error:
        return False
    return True

def ipv6addr(remoteServer):  # Check IPv6
    try:
        socket.inet_pton(socket.AF_INET6, remoteServer)
    except socket.error:
        return False
    return True

def httppp(req1):
    try:
        response = requests.get(req1)
    except requests.ConnectionError:
        print("")

    try:
        if response.status_code == 200:
            print("[+] Find Web Page", req1)
    except NameError:
        print("[+] No http Page")
        return False

def httppps(req2):
    try:
        response1 = requests.get(req2)
        if response1.status_code == 200:
            print("[+] Find Web Page", req2)
    except requests.ConnectionError:
        print("[+] No https Page")
        return False
    except NameError:
        print("[+] No https Page")
        return False

def cookiiie(req):

    response = requests.get(req)
    print(response.cookies)

def backup_file(req):
    backlst = [".backup",".bck",".old",".save",".bak",".sav","~",".copy",".old",".orig",".tmp",".txt",".back",".bkp",".bac",".tar",".gz",".tar.gz",".zip",".rar"]
    length = len(backlst)
    file = "/index.php"
    reqback = req + file
    for i in range(length):
        back = reqback + backlst[i]
        resback = requests.get(back)
        if resback.status_code == 200:
            print("[+] Found", back)

def wellknown(req):

    wellknownlst = ["/robots.txt", "/wp-admin/", "/.well-known/change-password", "/.well-known/coap",
                    "/.well-known/core", "/.well-known/csvm", "/.well-known/dnt-policy.txt", "/.well-known/hoba",
                    "/.well-known/host-meta", "/.well-known/host-meta.json", "/.well-known/http-opportunistic",
                    "/.well-known/keybase.txt", "/.well-known/mercure", "/.well-known/openorg",
                    "/.well-known/pki-validation", "/.well-known/security.txt",
                    "/.well-known/apple-app-site-association", "/.well-known/openpgpkey", "/.well-known/browserid",
                    "/.well-known/autoconfig/mail", "/.well-known/nodeinfo", "/.well-known/dat", "/admin/", "/phpbb/install/install.php",
                    "/../../../../etc/.passwd", "/log/log.php"]
    lengthwell = len(wellknownlst)
    for i in range(lengthwell):
        well = req + wellknownlst[i]
        reswell = requests.get(well)
        if reswell.status_code == 200:
            print("[+] Found", well)

if (ipv4addr(remoteServer) == False) and (ipv6addr(remoteServer) == False):  # If it's Name DNS resolve
    try:
        remoteServerIP = socket.gethostbyname(remoteServer)
        print("[+] Scanning", remoteServerIP)
    except socket.error:
        print("Server no reachable")
else:  # else Inverse resolve
    remoteServerIP = remoteServer
    try:
        remoteHostname = socket.gethostbyaddr(remoteServerIP)
        print("[+] Scanning", remoteHostname)
    except socket.error:
        print("Pas de hostname")

print("-" * 50)

if httppp(req1) != False:
    w = threading.Thread(target=wellknown, args=(req1,))
    b = threading.Thread(target=backup_file, args=(req1,))
    c = threading.Thread(target=cookiiie, args=(req1,))
    w.start()
    b.start()
    c.start()

if httppps(req2) != False:
    w1 = threading.Thread(target=wellknown, args=(req2,))
    b2 = threading.Thread(target=backup_file, args=(req2,))
    c2 = threading.Thread(target=cookiiie, args=(req2,))
    w1.start()
    b2.start()
    c2.start()