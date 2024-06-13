#include<stdio.h>
#include<string.h>
#include<stdlib.h>
int main(){
char v5[30]; // [rsp+20h] [rbp-40h] BYREF
char s2[13]; // [rsp+3Eh] [rbp-22h] BYREF
char s1[13]; // [rsp+4Bh] [rbp-15h] BYREF

void win(){
	printf("echo cat flag.txt");
}
void setupbuf()
{
  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  setbuf(stderr, 0LL);
}


setupbuf();
strcpy(s1, "y0ur d4rl1ng");
puts("What is your name? ");
read(0,v5,0x60);
printf("Nice to meet you, %s!\n", v5);
puts("My name is 'y0ur d4rl1ng', re-enter my name to get the flag! ");
read(0,s2,0xd);
if ( !strncmp(s1, s2, 12))
{
	puts("Here is your flag!");
	win();
}
else
	puts("None!");

return 0;
}
