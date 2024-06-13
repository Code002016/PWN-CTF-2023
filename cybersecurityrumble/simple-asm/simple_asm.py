#!/usr/bin/env python

import os
import struct
import sys
# 0x68732f2f6e69622f
# rax =r0
# rsp =r4
# rbx =r3
# rcx =r1
# rdx =r2
# rsi =r6
# rdi =r7
# r8 =r8
# r9 =r9
shellcode='''inc r1000000000000000000000000000000000000000
'''

print(shellcode)
lines = shellcode.strip().splitlines()
print(lines)
def main():
    print("Input your code, followed by END", flush=True)

    # Read in code

    source = []
    for line in lines:

        # Break at end
        if line == "END":
            break

        source.append(line)
    # Compile and execute code
    code = compile_asm(source)
    print("Executing code", flush=True)
    execute_shellcode(code)


def compile_asm(source):
    code = b""

    for line in source:
        # Skip empty lines and comments
        if not line:
            continue
        if line.strip().startswith("#"):
            continue

        # Split into mnemonic and operands
        instr, regs = line.split(maxsplit=1)
        regs = [parse_reg(r) for r in regs.split(",")]

        # Generate machine code
        match instr, regs:
            case "nul", [reg]: #"H1"
                code += bytes([0x48, 0x31, 0xC0 | reg | (reg << 3)])
            case "inc", [reg]: #"b'\xfe"
                code += bytes([0x48, 0xFF, 0xC0 | reg])
            case "add", [reg_dst, reg_src]:  
                code += bytes([0x48, 0x01, 0xC0 | reg_dst | (reg_src << 3)])
            case _:
                print(f"Unknown instruction: {line}", flush=True)
                sys.exit()
    # from pwn import disasm,context
    # context.arch = "amd64"
    # print(disasm(code))
    # print(code)
    return code


def parse_reg(reg):
    # Parse register number
    reg = reg.strip()
    assert reg.startswith("r")
    return int(reg[1:])


def execute_shellcode(code):
    # Align code to multiple of page size
    if len(code) % 0x1000:
        code += b"\xcc" * (0x1000 - (len(code) % 0x1000))

    # Build ELF file in memory
    elf = b""

    # ELF header
    elf += b"\x7fELF\x02\x01\x01\x03\0\0\0\0\0\0\0\0\x02\0\x3e\0\x01\0\0\0\0\0\0\x01\0\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\x38\0\x01\0\0\0\0\0\0\0"

    # Program header
    elf += b"\x01\0\0\0\x07\0\0\0\0\x10\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x01\0\0\0\0"
    elf += struct.pack("<Q", len(code)) * 2
    elf += b"\0\x10\0\0\0\0\0\0"

    # Pad to whole page
    elf = elf.ljust(0x1000, b"\0")

    # Shellcode
    elf += code

    # Put ELF into memfd
    memfd = os.memfd_create("sc")
    f = os.fdopen(memfd, mode="wb")
    f.write(elf)
    f.flush()

    # Execute memfd
    os.execve(memfd, ["sc"], {})
    print("execve failed!", flush=True)


if __name__ == "__main__":
    main()
    
    
