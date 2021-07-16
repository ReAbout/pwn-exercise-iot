#include <stdio.h>
#include <string.h>
int func2(int c ) { 
    int d = c+10;
    return d;
 }
int func1(int a,int b) {
  int c = a+b;
  c = func2(c);
  return c;
}
int main(int argc, char **argv) {
  int out = func1(1,2);
  printf("OUT %d",out);
  return 0;
}
