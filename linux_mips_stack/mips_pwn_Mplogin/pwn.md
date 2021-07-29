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

### 栈地址泄露

` sub_400840`函数读取数据到v1但是未验证最后一位字符，如果输入一个24字节并且前5字节是admin的字符串，当再次printf时候就会打印泄露数据。    
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

`qemu-mipsel  -L ./ Mplogin  | hexdump -C` 可以通过hexdump查看返回的hex。    



### 栈溢出
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

## Ref

- https://xuanxuanblingbling.github.io/ctf/pwn/2020/09/24/mips/