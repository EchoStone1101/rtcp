// #include "rtcp.h"
#include <sys/types.h> 
#include <sys/socket.h> 
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
struct timeval start, end;

/// Active open

int main() {
    socket(10, 0, 0);
    sleep(5); // Wait for RIP
    connect(10, NULL, 0);
    ssize_t sent = 0;
    ssize_t tot = (1l<<25); // 32MB

    double percentage = 0;

    gettimeofday(&start, NULL);
    int flag[5] = {0};

    while (sent < tot) {
        ssize_t _sent = send(10, NULL, 0, 0);
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

    
    close(10);
    while(1);
    return 0;
}