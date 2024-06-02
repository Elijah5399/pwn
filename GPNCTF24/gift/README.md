- Given a binary with no protections. i.e. No RELRO, NX disabled, PIE disabled, no canary

- It was created using assembly code and gadgets are sparse.

- Buffer overflow where we can overwrite up to 16 bytes (overwrite RIP + another 8 bytes)

- Only need 1 overwrite (8 bytes) which causes the sys_read to change RAX to 322, then change RIP to the xor rdx, rdx; syscall instruction.

- Doing so we call syscall with RAX = 322, RSI = address provided to sys_read, RDX = 0. If our payload started with /bin/sh\x00 we would get a shell.