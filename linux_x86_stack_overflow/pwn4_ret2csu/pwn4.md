# PWN Exercise - ret2csu

## 准备

### 64位函数参数调用
- 当参数少于7个时， 参数从左到右放入寄存器: rdi, rsi, rdx, rcx, r8, r9。
- 当参数为7个以上时，前 6 个与前面一样， 但后面的依次从 “右向左” 放入栈中，即和32位汇编一样。

## 题目
源码：
```c
#undef _FORTIFY_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void vulnerable_function() {
    char buf[128];
    read(STDIN_FILENO, buf, 512);
}

int main(int argc, char** argv) {
    write(STDOUT_FILENO, "Hello, World\n", 13);
    vulnerable_function();
}
```

编译：`gcc -no-pie -z norelro -fno-stack-protector pwn4.c -o pwn4`

checksec
```
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```