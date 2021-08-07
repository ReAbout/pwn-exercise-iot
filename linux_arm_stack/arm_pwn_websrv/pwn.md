# ARM Stack OverFlow


## 0x00 知识准备
### gdb调试子进程
```
set follow-fork-mode child
```

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
`handle_single_request`是处理请求的的函数，http_dest指针指的是v5的之上空间，这ida识别有点问题，正常该空间大小是
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
`sudo qemu-arm -g 1234 -L /usr/arm-linux-gnueabihf/ ./websrv ` 


0x00011250
0x00011468
## 0x02 EXP



## Ref


- https://github.com/saelo/armpwn  