#include "rtcp.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>

/// Tests basic linking from C to Rust.

int main() {
    socket(0, 1, 2);
    bind(3, NULL, 4);
    listen(5, 6);
    connect(7, NULL, 8);
    accept(9, NULL, 10);
    close(11);
    char a[] = "1.2.3.4";
    char b[] = "7890";
    getaddrinfo(a, b, NULL, NULL);

    const char msg[] = "write works\n";
    write(STDOUT_FILENO, msg, strlen(msg));

    return 0;
}