#!/usr/bin/perl
use strict;
use DynaLoader;
use IPC::Open2;

print "Disassemble what?\n";
$| = 1;
my $s = 42;
# void *sys_mmap(addr, len, prot, flags, fd, off)
# prot == 2 -> Pages may be written
my $p = syscall(9, 0, $s, 2, 33, -1, 0);
# ssize_t read(fd, void *buf, size_t count)
# read 42 characters from stdin into p
syscall(0, 0, $p, $s);
my $c = unpack "P$s", pack("Q", $p);

open2 my $out, my $in, "ndisasm -b64 -";
print $in $c;
close $in;
for (<$out>) {
	print $_;
	if (/syscall|sysenter|int|0x3b/) {
		die "no hax pls";
	}
}

print "Looks safe.\n";
# mprotect(addr, len, prot)
# prot == 4 -> PROT_EXEC https://sites.uclouvain.be/SystInfo/usr/include/bits/mman.h.html
syscall(10, $p, $s, 4);
&{DynaLoader::dl_install_xsub("", $p)};
