#ifndef __RTCP_H
#define __RTCP_H

/**
 * POSIX-compatible socket library supporting TCP protocol on IPv4, based 
 * on rust-implemented TCP protocol stack.
 */

#include <sys/types.h> 
#include <sys/socket.h> 
#include <netdb.h>

// Initialize RTCP library.
void __rtcp_init(void);

// This attribute makes the loader invoke this function before main()
// We use this to invoke the initializer of RTCP library.
void __attribute__ ((constructor)) _rtcp_init(void) {
    __rtcp_init();
}

// Returns whether the FILDES is a RTCP managed socket
int __rtcp_fildes_is_sock(int fildes);


// Fallback to normal syscalls
int __real_close(int fildes);
ssize_t __real_read(int fildes, void *buf, size_t nbyte);
ssize_t __real_write(int fildes, const void *buf, size_t nbyte);


/**
 * @see [POSIX.1-2017:socket](http://pubs.opengroup.org/onlinepubs/ * 9699919799/functions/socket.html)
 */
int __wrap_socket(int domain, int type, int protocol);

/**
 * @see [POSIX.1-2017:bind](http://pubs.opengroup.org/onlinepubs/ * 9699919799/functions/bind.html)
 */
int __wrap_bind(int socket, const struct sockaddr *address, socklen_t address_len);

/**
 * @see [POSIX.1-2017:listen](http://pubs.opengroup.org/onlinepubs/ * 9699919799/functions/listen.html)
 */
int __wrap_listen(int socket, int backlog);

/**
 * @see [POSIX.1-2017:connect](http://pubs.opengroup.org/onlinepubs/ * 9699919799/functions/connect.html)
 */
int __wrap_connect(int socket, const struct sockaddr *address, socklen_t address_len);

/**
 * @see [POSIX.1-2017:accept](http://pubs.opengroup.org/onlinepubs/ * 9699919799/functions/accept.html)
 */
int __wrap_accept(int socket, struct sockaddr *address, socklen_t *address_len);

/**
 * @see [POSIX.1-2017:write](http://pubs.opengroup.org/onlinepubs/ * 9699919799/functions/recv.html)
 */
ssize_t __wrap_recv(int socket, void *buffer, size_t length, int flags);

/**
 * @see [POSIX.1-2017:write](http://pubs.opengroup.org/onlinepubs/ * 9699919799/functions/send.html)
 */
ssize_t __wrap_send(int socket, const void *buffer, size_t length, int flags);

/**
 * @see [POSIX.1-2017:read](http://pubs.opengroup.org/onlinepubs/ * 9699919799/functions/read.html)
 */
ssize_t __wrap_read(int fildes, void *buf, size_t nbyte) {
    if (__rtcp_fildes_is_sock(fildes)) {
        // recv() with zero flag
        return __wrap_recv(fildes, buf, nbyte, 0);
    }
    return __real_read(fildes, buf, nbyte);
}

/**
 * @see [POSIX.1-2017:write](http://pubs.opengroup.org/onlinepubs/ * 9699919799/functions/write.html)
 */
ssize_t __wrap_write(int fildes, const void *buf, size_t nbyte) {
    if (__rtcp_fildes_is_sock(fildes)) {
        // recv() with zero flag
        return __wrap_send(fildes, buf, nbyte, 0);
    }
    return __real_write(fildes, buf, nbyte);
}

/**
 * @see [POSIX.1-2017:close](http://pubs.opengroup.org/onlinepubs/ * 9699919799/functions/close.html)
 */
int __wrap_close(int fildes);

/**
 * @see [POSIX.1-2017:getaddrinfo](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/getaddrinfo.html) */
int __wrap_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints,
                        struct addrinfo **res);


#endif