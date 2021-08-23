# pwn-exercise
My PWN 练习题。   
> 相关文件在对应的文件夹下。   
> 异构PWN技能栈，适合IoT安全研究者。    
## 0x01 Linux x86

### stack 


1. [初探栈溢出](./linux_x86_stack_overflow/pwn0_stack_overflow/pwn0.md)   
> 知识点：pwndbg & pwntools & 保护机制 & 栈溢出    
2. [ret2shellcode](./linux_x86_stack_overflow/pwn1_ret2shellcode/pwn1.md)
> 知识点：pwn checksec & ret2shellcode   
3. [ret2syscall](./linux_x86_stack_overflow/pwn2_ret2syscall/pwn2.md)   
> 知识点：ROPgadget & ret2syscall
4. [ret2libc 三连弹](./linux_x86_stack_overflow/pwn3_ret2libc/pwn3.md)
5. [ret2csu](./linux_x86_stack_overflow/pwn4_ret2csu/pwn4.md)   
6. [ret2dlresolve](./linux_x86_stack_overflow/pwn5_ret2dlresolve/pwn5.md)

### heap

### string format



## 0x02 Linux ARM

### stack 
1. [初探ARM PWN](./linux_arm_stack/arm_pwn_typo/pwn.md)  
> 知识点：ARM函数调用约定 & qemu调试 & ARM ret2shellcode &ARM RoP & ARM ret2syscall

2. [ARM WebServer](./linux_arm_stack/arm_pwn_websrv/pwn.md)  
> 知识点：qemu调试子进—Patch fork & 反弹shellcode

## 0x03 Linux MIPS

### stack 
1. [初探MIPS PWN](./linux_mips_stack/mips_pwn_Mplogin/pwn.md)  
> 知识点：MIPS函数调用约定 & MIPS寄存器 & MIPS ret2shellcode 
2. [MIPS RoP](./linux_mips_stack/mips_pwn_1/pwm.md)   
>知识点：MIPS RoP
3. [RealWrold CC](./linux_mips_stack/mips_iot_cc/pwm.md)
> 知识点： 00截断
## Ref
- https://ctf-wiki.org/
- https://xuanxuanblingbling.github.io/

