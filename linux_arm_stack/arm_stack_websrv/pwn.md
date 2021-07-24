# ARM Stack OverFlow


## 0x00 ARM PWN 知识准备
### Qemu
在1234端口开启gdbserver `-g` 1234    
`sudo qemu-arm -g 1234 -L /usr/arm-linux-gnueabihf/ ./websrv ` 
- ARM指令集  

## 0x01 PWN

### 1.题目
可选择2种模式：    
- 黑盒模式：无binary的情况下，web服务RCE。   
- 灰盒模式：提供binary，web服务RCE。  

作者提供的binary所有保护全开了，需要通过/proc/self/map泄露信息，这不适合qemu启动，推荐在树莓派上运行。   
本次题目提供的二进制重新编译，关闭栈保护，通过qemu模拟运行，采用灰盒模式进行PWN。    

程序：[binary & html](./bin/)
环境：ubuntu 16.04    
启动：`sudo qemu-arm -L /usr/arm-linux-gnueabihf/ ./websrv `    
>`/lib/ld-linux-armhf.so.3: No such file or directory`报错。    
sudo apt-get install libc6-armhf-cross 添加参数 -L    

[Ref]:https://github.com/saelo/armpwn  

### 2.分析
```
$ pwn checksec ./websrv 
[*] '/home/mi/CTF/pwn-exercise/linux_arm_stack/arm_stack_httpd/bin/websrv'
    Arch:     arm-32-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
所有安全保护都开了，但是qemu不支持nx，相当于没开启。    
#### 目录穿越任意读


#### 栈溢出




## 0x02 EXP
