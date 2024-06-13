from pwn import *
r=remote("pwn.dvc.tf", 8888)
r.recvuntil(b"-mb28")
string =r.recv(8)
subprocess.run(["hashcash", "-mb28", string])