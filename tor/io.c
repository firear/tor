#include "io.h"
#include "crc32.h"
#include "tor.h"
#include <pcap.h>
#include <stdlib.h>
#include <time.h>

#include "debug.h"

int io_conn(io_t* io, const char* ip, uint16_t port, CB_CONN conncb)
{
    int ret = 0;
    if (!io->cb_connected) {
        io->cb_connected = conncb;
        io->addr.tcp_ack = io->addr.tcp_seq = 0;
        io->addr.is_serveraddr = 1;
        io_send(io, DTYPE_SYN, -1, NULL, 0, &io->addr);
    } else {
        LOGE("some one is connecting, wait!");
        ret = -1;
    }

    return 0;
}

int io_accept(io_t* io, CB_CONN acceptcb)
{
    io->cb_accpeted = acceptcb;
    return 0;
}

//////////////////////////////

void updatetun(tor_t* tun, void* user)
{
    kcp_update(tun);
}

int __gencid(cm_t* cm)
{
    int i = 0;
    for (; i < 1000; i++) {
        if (!cm_has(cm, i)) {
            break;
        }
    }
    if (i > 1000) {
        LOGE("too many connections!");
        i = -1;
    }
    return i;
}

int __syn_ack(io_t* io, int cid)
{
    return io_send(io, DTYPE_ACK | DTYPE_SYN, cid, NULL, 0, &io->addr);
}

int __accepted(io_t* io, io_head_t* d)
{
    tor_t* tun = new_kcp_tunnel(io, d->cid, 1400);
    cm_entry_t* e = cm_get(&io->cm, d->cid);
    e->cid = d->cid;
    e->tun = tun;
    io->cb_accpeted(tun);
    return 0;
}

void __onconnected(io_t* io, io_head_t* d)
{
    // TODO check
    if (io->cb_connected) {
        io_send(io, DTYPE_ACK, d->cid, NULL, 0, &io->addr);
        tor_t* tun = new_kcp_tunnel(io, d->cid, 1400);
        cm_entry_t* e = cm_get(&io->cm, d->cid);
        e->cid = d->cid;
        e->tun = tun;
        io->cb_connected(tun);
        io->cb_connected = NULL;
    }
}

int io_startloop(io_t* io)
{
    char data[1600];
    // unsigned long long cur = 0, last = 0;
    io->stat = IO_STAT_RUNNING;
    while (io->stat == IO_STAT_RUNNING) {
        int readlen = io->recvfromraw(io, data, sizeof(data), &io->addr);
        if (readlen >= sizeof(io_head_t)) {
            io_head_t* d = (io_head_t*)data;
            if (readlen == sizeof(io_head_t) + d->dlen) {
                uint32_t crc = crc32(&d->cid, readlen - offsetof(io_head_t, cid));
                if (crc == d->crc) {
                    switch (d->type) {
                    case DTYPE_SYN: {
                        if (d->cid == -1) {
                            int cid = __gencid(&io->cm); // generate new cid
                            if (cid >= 0) {
                                __syn_ack(io, cid);
                            }
                        } else {
                            LOGE("syn except cid=-1 buf %u", d->cid);
                        }
                        break;
                    }
                    case DTYPE_SYN | DTYPE_ACK: {
                        __onconnected(io, d);
                        break;
                    }
                    case DTYPE_ACK: {
                        __accepted(io, d);
                        break;
                    }
                    case DTYPE_PSH | DTYPE_ACK: {
                        cm_entry_t* c = cm_search(&io->cm, d->cid);
                        if (c) {
                            kcp_input(c->tun, &io->addr, d->payload, d->dlen);
                        } else {
                            LOGE("no c found cid:%d", d->cid);
                        }
                        break;
                    }
                    default:
                        LOGI("type ignore data %d", d->type);
                        break;
                    }
                } else {
                    LOGI("crc ingore");
                }
            } else {
                LOGI("len mismatch ignore %d", d->dlen);
            }
        } else if (readlen == 0) {
            // LOGE("readlen = 0");
        } else {
        }
        // cur = gethrtime_us();
        // unsigned long long td = cur - last;
        // if (td > 10000) {
        //     last = cur;
        //     for_each(&io->cm, updatetun, NULL);
        // } else {         
        //     usleep(10000 - td);
        // }
    }
    return 0;
}

void __closekcptun(tor_t* tun, void* user)
{
    release_kcp_tunnel(tun);
}

int io_del_tunnel(io_t* io, uint32_t cid)
{
    cm_entry_t* c = cm_search(&io->cm, cid);
    if (c) {
        release_kcp_tunnel(c->tun);
        cm_del(&io->cm, cid);
    }
    return 0;
}

int io_close(io_t* io)
{
    int ret = 0;

    for_each(&io->cm, __closekcptun, NULL);
    cm_cleanup(&io->cm);

    io->stat = IO_STAT_CLOSED;
    if (io->closeraw) {
        ret = io->closeraw(io);
    }

    return ret;
}

int io_send(io_t* io, uint8_t type, uint32_t cid, const void* data, size_t datalen, addrinfo_t* addr)
{
    int totallen = sizeof(io_head_t) + datalen;
    io_head_t* d = malloc(totallen);
    d->type = type, d->crc = 0, d->cid = cid, d->dlen = datalen;
    if (datalen > 0) {
        memcpy(d->payload, data, datalen);
    }
    d->crc = crc32(&d->cid, d->dlen + sizeof(io_head_t) - offsetof(io_head_t, cid));
    LOGV("%s: t=%x, cid=%d", __func__, type, cid, totallen);
    int ret = io->sendtoraw(io, d, totallen, addr);
    free(d);

    return ret;
}