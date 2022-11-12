#include "rtcp.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>

/// Active open

int main() {
    socket(10, 0, 0);
    sleep(5); // Wait for RIP
    connect(10, NULL, 0);
    send(10, NULL, 0, 0); // Can send immediately
    send(10, NULL, 0, 0); // ...twice
    sleep(6);
    close(10);

    while(1);
    return 0;
}