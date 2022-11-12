#include "rtcp.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>

/// Passive open

int main() {
    socket(10, 0, 0);
    listen(10, 0);

    ssize_t rcvd = 0;
    ssize_t tot = 0;
    while ((rcvd = recv(10, NULL, 0, 0)) > 0) {
        tot += rcvd;
    }

    printf("======================\n[Received] %ld\n======================\n", tot);
    close(10);

    while(1);
    return 0;
}