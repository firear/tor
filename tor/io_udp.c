#include "io_udp.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if __linux
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#include <sys/types.h>

#include "debug.h"

typedef struct io_udp_s {
    io_t io;
    int sock_fd;
} io_udp_t;

int _recvfrom(struct io_s* io, void* buffer, size_t length, addrinfo_t* addr)
{
    io_udp_t* udpio = (io_udp_t*)io;
    socklen_t len;
    return recvfrom(udpio->sock_fd, buffer, length, 0, &addr->sockaddr_peer.sa, &len);
}

int _sendto(struct io_s* io, const void* data, size_t datalen, const addrinfo_t* addrinfo)
{
    printf("%s %zu\n", __func__, datalen);
    io_udp_t* udpio = (io_udp_t*)io;
    const sockaddr_u* addr = &addrinfo->sockaddr_peer;
    if (addr->sa.sa_family == AF_INET) {
        return sendto(udpio->sock_fd, data, datalen, 0, &addr->sa, sizeof(struct sockaddr_in));
    } else if (addr->sa.sa_family == AF_INET6) {
        return sendto(udpio->sock_fd, data, datalen, 0, &addr->sa, sizeof(struct sockaddr_in6));
    } else {
        LOGE("%s: unknown addrtype %d", __func__, addr->sa.sa_family);
        return -1;
    }
}

io_t* initudpserver(const char* serverip, uint16_t server_port, CB_CONN cb)
{
    io_udp_t* ret = calloc(1, sizeof(io_udp_t));
    struct sockaddr_in ser_addr;

    ret->sock_fd = socket(AF_INET, SOCK_DGRAM, 0); // AF_INET:IPV4;SOCK_DGRAM:UDP
    if (ret->sock_fd < 0) {
        printf("create socket fail!\n");
        free(ret);
        return NULL;
    }

    memset(&ser_addr, 0, sizeof(ser_addr));
    ser_addr.sin_family = AF_INET;
    inet_pton(AF_INET, serverip, &ser_addr.sin_addr.s_addr);
    // ser_addr.sin_addr.s_addr = htonl(INADDR_ANY); // IP地址，需要进行网络序转换，INADDR_ANY：本地地址
    ser_addr.sin_port = htons(server_port); // 端口号，需要网络序转换

    if (bind(ret->sock_fd, (struct sockaddr*)&ser_addr, sizeof(ser_addr)) < 0) {
        printf("socket bind fail!\n");
        free(ret);
        return NULL;
    }

    // fcntl(ret->sock_fd, F_SETFL, fcntl(ret->sock_fd, F_GETFL) | O_NONBLOCK);
    ret->io.sendtoraw = _sendto;
    ret->io.recvfromraw = _recvfrom;
    cm_init(&ret->io.cm);
    io_accept(&ret->io, cb);
    return (io_t*)ret;
}

io_t* initudpclient(const char* serverip, const uint16_t server_port, CB_CONN cb)
{
    io_udp_t* ret = calloc(1, sizeof(io_udp_t));

    ret->sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ret->sock_fd < 0) {
        printf("create socket fail!\n");
        return NULL;
    }

    inet_pton(AF_INET, serverip, &ret->io.addr.sockaddr_peer.sin.sin_addr);

    ret->io.addr.sockaddr_peer.sin.sin_family = AF_INET;

    ret->io.addr.sockaddr_peer.sin.sin_port = htons(server_port);

    // int r = connect(ret->sock_fd, &ret->sockaddr_peer, sizeof(ret->sockaddr_peer));

    // fcntl(ret->sock_fd, F_SETFL, fcntl(ret->sock_fd, F_GETFL) | O_NONBLOCK);
    ret->io.sendtoraw = _sendto;
    ret->io.recvfromraw = _recvfrom;

    cm_init(&ret->io.cm);

    io_conn((io_t*)ret, serverip, server_port, cb);

    return (io_t*)ret;
}
