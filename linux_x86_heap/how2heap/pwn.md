# 堆漏洞利用——how2heap

- https://github.com/shellphish/how2heap
- 实验环境：ubuntu 16.04

## 0x00 基础知识

## 0x01 first_fit
演示的是glibc malloc分配。
- 代码：[first_fit.c](./first_fit.c)
- 编译: `gcc  -no-pie  first_fit.c -o first_fit`
```
char* a = malloc(0x512);
char* b = malloc(0x256);
char* c;
strcpy(a, "this is A!");
free(a);
c = malloc(0x500);
strcpy(c, "this is C!");
```
	
这个其实演示UAF漏洞，分配了给a指针第一个chunk大小0x512，当free之后会被放入large bins中，当malloc分配0x500正好在一个数组链表中，就分配和a指针同一块内存空间，a如果再次调用就变成c指针修改的内容了。

>large bin 每组bin表示一组size范围的不是具体size，eg bins[126]保存长度[0x400,0x440]的chunk

## calc_tcache_idx
- 代码：[calc_tcache_idx.c](./calc_tcache_idx.c)

## Ref
- https://github.com/shellphish/how2heap