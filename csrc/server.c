// #include "rtcp.h"
#include <sys/types.h> 
#include <sys/socket.h> 
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

/// Passive open

int main() {

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("sock");
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(0x0a640101);
    addr.sin_port = 5678;

    if (bind(sock, (const struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
    }

    if (listen(sock, 4) < 0) {
        perror("listen");
    }

    // ssize_t rcvd = 0;
    // ssize_t tot = 0;
    // while ((rcvd = recv(10, NULL, 0, 0)) > 0) {
    //     tot += rcvd;
    // }

    // printf("======================\n[Received] %ld\n======================\n", tot);

    int connfd = accept(sock, NULL, NULL);
    if (connfd < 0) {
        perror("accept");
        return 0;
    }
    
    sleep(3);
    if (close(connfd) < 0) {
        perror("close");
    }

    while(1);
    return 0;
}