#include "rtcp.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>

/// Active open

int main() {
    socket(10, 0, 0);
    listen(10, 0);
    sleep(10);
    close(10);
    
    while(1);
    return 0;
}