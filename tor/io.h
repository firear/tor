#ifndef __IO_H__
#define __IO_H__

#include "cm.h"
#include "tor.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum DTYPE {
    DTYPE_SYN = 1,
    DTYPE_ACK = 2,
    DTYPE_PSH = 4,
};
#pragma pack(push)
#pragma pack(1)
typedef struct io_head_s {
    uint8_t nonce[16];
    uint8_t type;
    uint32_t crc;
    uint32_t cid;
    uint16_t dlen;
    uint8_t payload[0];
} io_head_t;
#pragma pack(pop)

enum IO_STAT{
    IO_STAT_INIT = 0,
    IO_STAT_RUNNING,
    IO_STAT_CLOSED,
};

typedef void (*CB_CONN)(tor_t* tun);
// 单线程
struct io_s {
    cm_t cm;
    addrinfo_t addr;
    uint8_t stat; //

    CB_CONN cb_connected;
    CB_CONN cb_accpeted;

    void *user;

    int (*recvfromraw)(struct io_s* io, void* data, size_t datalen, addrinfo_t* addr);

    int (*sendtoraw)(struct io_s* io, const void* data, size_t datalen, const addrinfo_t* addr);

    int (*closeraw)(struct io_s* io);
};

#ifdef __cplusplus
extern "C" {
#endif

int io_conn(io_t* io, const char* ip, uint16_t port, CB_CONN conncb);
int io_accept(io_t* io, CB_CONN acceptcb);
int io_del_tunnel(io_t* io, uint32_t cid);
int io_close(io_t* io);
int io_send(io_t* io, uint8_t type, uint32_t cid, const void* data, size_t datalen, addrinfo_t* addr);
int io_startloop(io_t* io);

#ifdef __cplusplus
}
#endif
#endif
