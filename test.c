#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main() {
    struct addrinfo hints, *listp, *p;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG | AI_NUMERICSERV;
    const char port[] = "51234";
    getaddrinfo(NULL, port, &hints, &listp);

    int listenfd;
    for (p = listp; p; p->ai_next) {
        if ((listenfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0)
            continue;
        
        // setsockopt(listenfd, )

        if (bind(listenfd, p->ai_addr, p->ai_addrlen) == 0)
            break;
        close(listenfd);
    }

    freeaddrinfo(listp);
    if (!p)
        return -1;
    
    if (listen(listenfd, 1024) < 0) {
        close(listenfd);
        return -1;
    }

    struct sockaddr addr;
    
    connect(listenfd, );
    return 0;
}