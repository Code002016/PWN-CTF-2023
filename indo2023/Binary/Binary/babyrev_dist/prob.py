from pwn import *

p = process('./prob')
p.sendline(b'HWKLERGNEUPMQGDA-ERIGADPQWJVIGNEG')
