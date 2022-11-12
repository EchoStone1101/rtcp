#include "rtcp.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>

/// Passive open

int main() {
    socket(10, 0, 0);
    listen(10, 0);
    sleep(10);
    recv(10, NULL, 0, 0);
    sleep(5);
    recv(10, NULL, 0, 0); // Receive when REMOTE has closed
    close(10);

    while(1);
    return 0;
}