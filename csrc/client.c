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

    // sleep(5); should not need this now

    int sock = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(0x0a640101);
    addr.sin_port = 5678;

    // without bind(); RTCP should pick appropriate (src_ip, src_port)
    
    if (connect(sock, (const struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        return 0;
    }


    ssize_t sent = 0;
    ssize_t tot = (1l<<25); // 32MB
    void *data = malloc(tot);
    for (int i=0;i<tot/4;i++) {
        ((int*)data)[i] = i;
    }

    double percentage = 0;

    gettimeofday(&start, NULL);
    int flag[5] = {0};

    while (sent < tot) {
        ssize_t _sent = write(sock, sent + data, tot-sent);
        sent += _sent;

        percentage = (double)sent / tot * 100;
        printf ("%% %lf\n", percentage);

        if (percentage >= 80) {
            if (!(flag[4])) {
                gettimeofday(&end, NULL);
                double elapsed = ((end.tv_sec  - start.tv_sec) * 1000000u +
                        end.tv_usec - start.tv_usec) / 1.e6;
                printf("Elapsed: %lf \n", elapsed);
                flag[4] = 1;
            }
        }
        else if (percentage >= 60) {
            if (!(flag[3])) {
                gettimeofday(&end, NULL);
                double elapsed = ((end.tv_sec  - start.tv_sec) * 1000000u +
                        end.tv_usec - start.tv_usec) / 1.e6;
                printf("Elapsed: %lf \n", elapsed);
                flag[3] = 1;
            }
        }
        else if (percentage >= 40) {
            if (!(flag[2])) {
                gettimeofday(&end, NULL);
                double elapsed = ((end.tv_sec  - start.tv_sec) * 1000000u +
                        end.tv_usec - start.tv_usec) / 1.e6;
                printf("Elapsed: %lf \n", elapsed);
                flag[2] = 1;
            }
        }
        else if (percentage >= 20) {
            if (!(flag[1])) {
                gettimeofday(&end, NULL);
                double elapsed = ((end.tv_sec  - start.tv_sec) * 1000000u +
                        end.tv_usec - start.tv_usec) / 1.e6;
                printf("Elapsed: %lf \n", elapsed);
                flag[1] = 1;
            }
        }
    }
    gettimeofday(&end, NULL);
    double elapsed = ((end.tv_sec  - start.tv_sec) * 1000000u +
                    end.tv_usec - start.tv_usec) / 1.e6;
    printf("======================\n[Sent] %ld \nElapsed: %lf\n======================\n", sent, elapsed);


    if (close(sock) < 0) {
        perror("close");
    }

    while(1);
    return 0;
}