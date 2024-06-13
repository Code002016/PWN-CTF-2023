from pwn import *
from ctypes import *
import time

context.log_level = 'debug'
context.arch = "amd64"

e = context.binary = ELF('./source',checksec=False)



def __int64 __fastcall sub_77A( unsigned __int8 a1, int a2)
{
  return (a1 << a2) | (a1 >> (-a2 & 7));
}

long long int v7[3];

v7[0] = 0x26666FE8EA686A28LL;
v7[1] = 0xAEE8EBE666666666LL;
v7[2] = 0xEBA5EB4E666E6E66LL;
v8 = -20571;
v9 = 0;
v10[0] = 0;
for ( i = 0; i <= 25; ++i )
  *(v10 + i) = sub_77A(*(v7 + i), 3LL);

# r= e.process()


