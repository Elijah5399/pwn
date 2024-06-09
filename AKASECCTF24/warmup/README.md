## warmup

- We are given a global variable with a large size

- Buffer overflow, with only 2 instructions we could possibly add via ROP

- Overcome the 2 instruction limit by doing a stack pivot into the global variable

- From there, form an ROP chain which does execve("/bin/sh")