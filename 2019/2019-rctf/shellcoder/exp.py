from pwn import *
ru=lambda s:p.recvuntil(s)
rl=lambda :p.recvline()
sl=lambda s:p.sendline(s)
sd=lambda s:p.send(s)
context(log_level='debug',os='linux',arch='amd64')

p=None
libcpath=None
binarypath='./shellcoder'
def run(ip=None,port=None):
    global p
    if libcpath and binarypath:
        p=process(binarypath,env={'LD_PRELOAD':libcpath})
    elif ip and port:
        p=remote(ip,port)
    else binarypath:
        p=process(binarypath)

is_debug=False
def debugf(s=''):
    if is_debug:
        gdb.attach(p,s)


def exp():
    run()
    ru(':')
    
    p.interactive()
exp()