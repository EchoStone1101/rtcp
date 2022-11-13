// #include "rtcp.h"
#include <sys/types.h> 
#include <sys/socket.h> 
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>
#include <stdlib.h>
struct timeval start, end;

/// Use POSIX like interface

int main() {

    int sock = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(0x0a640102);
    addr.sin_port = 5678;

    if (bind(sock, (const struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 0;
    }

    addr.sin_addr.s_addr = htonl(0x0a640101);
    if (connect(sock, (const struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        return 0;
    }

    ssize_t tot = (1l<<25); // 32MB
    void *data = malloc(tot);

    ssize_t rcvd = 0, _rcvd;
    while ((_rcvd = read(sock, data + rcvd, tot - rcvd)) > 0) {
        rcvd += _rcvd;
    }
    printf("======================\n[Received] %ld\n======================\n", rcvd);

    if (close(sock) < 0) {
        perror("close");
    }

    return 0;
}