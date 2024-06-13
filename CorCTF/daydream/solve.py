from pwn import *
context.log_level = 'debug'
context.arch = "amd64"

r=remote('pwn-daydream-daydream-24b3f8e606d28c40.be.ax', 8080, ssl=True)