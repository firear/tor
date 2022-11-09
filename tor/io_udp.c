#include "io_udp.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

int _recvfrom(struct io_s* io, void* buffer, size_t length, void* addr)
{
    io_udp_t* udpio = (io_udp_t*)io;

    return recv(udpio->client_fd, buffer, length, 0);
}

int _sendto(struct io_s* io, const void* data, size_t datalen, const void* addr)
{
    printf("%s %zu\n", __func__, datalen);
    io_udp_t* udpio = (io_udp_t*)io;
    return send(udpio->client_fd, data, datalen, 0);
}

io_udp_t* initudpserver(uint16_t server_port)
{
    io_udp_t* ret = calloc(1, sizeof(io_udp_t));
    struct sockaddr_in ser_addr;

    ret->client_fd = socket(AF_INET, SOCK_DGRAM, 0); // AF_INET:IPV4;SOCK_DGRAM:UDP
    if (ret->client_fd < 0) {
        printf("create socket fail!\n");
        free(ret);
        return NULL;
    }

    memset(&ser_addr, 0, sizeof(ser_addr));
    ser_addr.sin_family = AF_INET;
    ser_addr.sin_addr.s_addr = htonl(INADDR_ANY); // IP地址，需要进行网络序转换，INADDR_ANY：本地地址
    ser_addr.sin_port = htons(server_port); // 端口号，需要网络序转换

    if (bind(ret->client_fd, (struct sockaddr*)&ser_addr, sizeof(ser_addr)) < 0) {
        printf("socket bind fail!\n");
        free(ret);
        return NULL;
    }

    ret->io.sendto = _sendto;
    ret->io.recvfrom = _recvfrom;
    return ret;
}

io_udp_t* initudpclient(const char* serverip, const uint16_t server_port)
{
    io_udp_t* ret = calloc(1, sizeof(io_udp_t));
    struct sockaddr_in ser_addr;

    ret->client_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ret->client_fd < 0) {
        printf("create socket fail!\n");
        return NULL;
    }

    memset(&ser_addr, 0, sizeof(ser_addr));

    inet_pton(AF_INET, serverip, &ser_addr.sin_addr);

    ser_addr.sin_family = AF_INET;

    ser_addr.sin_port = htons(server_port);

    int r = connect(ret->client_fd, &ser_addr, sizeof(ser_addr));

    ret->io.sendto = _sendto;
    ret->io.recvfrom = _recvfrom;

    return ret;
}
