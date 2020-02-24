from pwn import *
from sys import argv
from time import sleep

context.log_level = "INFO"

res = []

for i in range(1, 256):
    p = remote("modulo.ctf.jyoken.net", 80)
    p.recvuntil("n = ")
    p.sendline(str(i))
    p.recvuntil("Here you are: ")
    res.append(eval(p.recvline()))
    p.close()

print(res)
