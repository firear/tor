#include "tor/io_raw.h"
#include "tor/tor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "hthread.h"

#include "debug.h"

typedef struct udp2raw_s {
    int sock_fd;
    uint8_t stop;
    tor_t* tun;
    sockaddr_u addr;
    socklen_t addrlen;
} udp2raw_t;

HTHREAD_ROUTINE(in)
{
    udp2raw_t* ctx = userdata;
    char buf[1600];
    ctx->addrlen = sizeof(ctx->addr);
    while (!ctx->stop) {
        int len = recvfrom(ctx->sock_fd, buf, sizeof(buf), 0, &ctx->addr.sa, &ctx->addrlen);
        if (len > 0) {
            kcp_send(ctx->tun, buf, len);
        } else {
            LOGE("sockin recverror:%s", strerror(errno));
        }
    }
    return 0;
}

udp2raw_t* initudpserver(const char* serverip, uint16_t server_port)
{
    udp2raw_t* ret = calloc(1, sizeof(udp2raw_t));
    struct sockaddr_in ser_addr;

    ret->sock_fd = socket(AF_INET, SOCK_DGRAM, 0); // AF_INET:IPV4;SOCK_DGRAM:UDP
    if (ret->sock_fd < 0) {
        LOGE("create socket fail!");
        free(ret);
        return NULL;
    }

    memset(&ser_addr, 0, sizeof(ser_addr));
    ser_addr.sin_family = AF_INET;
    inet_pton(AF_INET, serverip, &ser_addr.sin_addr.s_addr);
    // ser_addr.sin_addr.s_addr = htonl(INADDR_ANY); // IP地址，需要进行网络序转换，INADDR_ANY：本地地址
    ser_addr.sin_port = htons(server_port); // 端口号，需要网络序转换

    if (bind(ret->sock_fd, (struct sockaddr*)&ser_addr, sizeof(ser_addr)) < 0) {
        LOGE("socket bind fail!\n");
        free(ret);
        return NULL;
    }

    return ret;
}

udp2raw_t* initudpclient(const char* serverip, const uint16_t server_port)
{
    udp2raw_t* ret = calloc(1, sizeof(udp2raw_t));

    ret->sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ret->sock_fd < 0) {
        printf("create socket fail!\n");
        return NULL;
    }

    ret->addrlen = sizeof(ret->addr.sin);
    inet_pton(AF_INET, serverip, &ret->addr.sin.sin_addr);

    ret->addr.sin.sin_family = AF_INET;

    ret->addr.sin.sin_port = htons(server_port);

    int r = connect(ret->sock_fd, &ret->addr.sa, sizeof(ret->addr.sin));

    return ret;
}

void recv_cb(tor_t* tun, const void* buf, int len)
{
    char addrstr[SOCKADDR_STRLEN];
    udp2raw_t* ctx = kcp_get_ctx(tun);
    int ret = sendto(ctx->sock_fd, buf, len, 0, &ctx->addr.sa, ctx->addrlen);
    sockaddr_str(&ctx->addr, addrstr, sizeof(addrstr));
    LOGV("%s recv %d ->%s ret=%d", __func__, len, addrstr, ret);
}

void on_connected(tor_t* tun)
{
    LOGI("%s %p", __func__, tun);
    udp2raw_t* ctx = initudpserver("127.0.0.1", 9999);
    ctx->tun = tun;
    kcp_set_ctx(tun, ctx);
    kcp_set_recvcb(tun, recv_cb);
    hthread_t tid = hthread_create(in, ctx);
}

void on_accepted(tor_t* tun)
{
    LOGI("%s %p", __func__, tun);
    udp2raw_t* ctx = initudpclient("127.0.0.1", 10000);
    ctx->tun = tun;
    kcp_set_ctx(tun, ctx);
    kcp_set_recvcb(tun, recv_cb);
    hthread_t tid = hthread_create(in, ctx);
}

/**
 * @brief
 *
 * openvpn -> udp:9999 -> raw -> raw -> udp: -> udp:10000(openvpn)
 *
 * ./udp2raw s enp3s0 icmp/fudp/ftcp [port]
 * ./udp2raw c enp3s0 icmp/fudp/ftcp 192.168.0.2 9999
 * @param argc
 * @param argv
 * @return int
 */
int main(int argc, char const* argv[])
{
    LOGV("init");

    io_t* io = NULL;
    const char* addr = "192.168.0.2";
    const char* devname = "enp3s0";
    const char* modestr = "icmp";
    RAWMODE mode = RAWMODE_ICMP;
    if (argc >= 4) {
        devname = argv[2];
        modestr = argv[3];
        if (!strcmp(modestr, "fudp")) {
            mode = RAWMODE_FUDP;
        } else if (!strcmp(modestr, "ftcp")) {
            mode = RAWMODE_FTCP;
        }

        if (argv[1][0] == 's') {
            int sport = atoi(argv[4]);
            io = initraw_server(mode, devname, NULL, sport, on_accepted);
        } else {
            addr = argv[4];
            int sport = atoi(argv[5]);
            io = initraw_client(mode, devname, addr, sport, on_connected);
        }
    }

    if (io) {
        io_startloop(io);
    }
    io_close(io);
    return 0;
}
