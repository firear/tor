#include "tor.h"
#include "crc32.h"
#include "ikcpriv.h"
#include "io.h"
#include "hthread.h"
#include <stdlib.h>
#include "htime.h"
#include "debug.h"

/******************************************************************************/

struct kcp_tunnel_s {
    RECV_CB recv_cb;
    void* ctx;

    hthread_t ktid;
    hmutex_t kmux;

    ikcpcb* kcp;
    io_t* io;
    int cid;
    addrinfo_t addrinfo;

    // heartbeat
    kcp_send_heartbeat_fn heartbeat_fn;
    uint64_t heartbeat_lastsendtime; // ms
    uint32_t heartbeat_interval; // ms
    //
    uint32_t last_ack;
    uint8_t stop;
};

// static unsigned int gettick_ms()
// {
// #ifdef _WIN32
//     return GetTickCount();
// #elif HAVE_CLOCK_GETTIME
//     struct timespec ts;
//     clock_gettime(CLOCK_MONOTONIC, &ts);
//     return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
// #else
//     struct timeval tv;
//     gettimeofday(&tv, NULL);
//     return tv.tv_sec * 1000 + tv.tv_usec / 1000;
// #endif
// }

/******************************************************************************/

int kcp_send(tor_t* ktun, const void* buf, int len)
{
    int retv;

    hmutex_lock(&ktun->kmux);
    retv = ikcp_send(ktun->kcp, buf, len);
    int current = gettick_ms();
    ikcp_update(ktun->kcp, current);
    hmutex_unlock(&ktun->kmux);
    return retv;
}

void kcp_input(tor_t* ktun, addrinfo_t* addr, const void* buf, int len)
{
    char rbuf[1536];

    memcpy(&ktun->addrinfo, addr, offsetof(addrinfo_t, tcp_seq));
    ktun->addrinfo.tcp_ack = addr->tcp_ack;
    addr->tcp_ack = addr->nxt_ack;

    hmutex_lock(&ktun->kmux);
    ikcp_input(ktun->kcp, buf, len);
    hmutex_unlock(&ktun->kmux);

    while (1) {
        hmutex_lock(&ktun->kmux);
        len = ikcp_recv(ktun->kcp, rbuf, sizeof(rbuf));
        hmutex_unlock(&ktun->kmux);
        if (len < 0) {
            break;
        }
        if (ktun->recv_cb) {
            ktun->recv_cb(ktun, rbuf, len);
        } else {
            LOGW("kcp_input no recv cb");
        }
    }
}

/******************************************************************************/

static int kcp_output(const char* buf, int len, ikcpcb* kcp, void* user)
{
    tor_t* ktun = (tor_t*)user;
    return io_send(ktun->io, DTYPE_PSH | DTYPE_ACK, ktun->cid, buf, len, &ktun->addrinfo);
}

HTHREAD_ROUTINE(kcp_update_thread)
{
    tor_t* ktun = (tor_t*)userdata;
    int current, next, len;
    char rbuf[1536];

    while (!ktun->stop) {
        // pthread_testcancel();
        hmutex_lock(&ktun->kmux);
        while (1) {
            len = ikcp_recv(ktun->kcp, rbuf, sizeof(rbuf));
            if (len < 0) {
                break;
            }
            LOGI("================================read some data here================================");
            ktun->recv_cb(ktun, rbuf, len);
        }
        current = gettick_ms();
        ikcp_update(ktun->kcp, current);
        next = ikcp_check(ktun->kcp, current);
        hmutex_unlock(&ktun->kmux);

        next -= current;
        if (next > 0) {
            hv_usleep(next * 1000);
        }
    }

    return 0;
}

/******************************************************************************/
void kcp_update(tor_t* ktun)
{
    hmutex_lock(&ktun->kmux);
    unsigned int current = gettick_ms();
    ikcp_update(ktun->kcp, current);
    hmutex_unlock(&ktun->kmux);
    if (ktun->heartbeat_fn && current - ktun->heartbeat_lastsendtime > ktun->heartbeat_interval) {
        ktun->heartbeat_lastsendtime = current;
        ktun->heartbeat_fn(ktun);
    }
}

void kcp_set_recvcb(tor_t* tunnel, RECV_CB recv_cb)
{
    tunnel->recv_cb = recv_cb;
}

void logwriter(const char* content, struct IKCPCB* kcp, void* user)
{
    LOGD("%s", content);
}

tor_t* new_kcp_tunnel(io_t* io, int cid, int mtu)
{
    LOGV("%s: cid=%d", __func__, cid);
    tor_t* ktun;

    ktun = (tor_t*)malloc(sizeof(tor_t));
    memset(ktun, 0, sizeof(tor_t));

    ktun->io = io;
    ktun->addrinfo = io->addr;
    ktun->cid = cid;
    ktun->kcp = ikcp_create(cid, ktun);

    ktun->kcp->logmask = 0xffffffff;
    ktun->kcp->writelog = logwriter;

    ikcp_setoutput(ktun->kcp, kcp_output);
    ikcp_setmtu(ktun->kcp, mtu + 8); // data + stream_header

    // normal: 0 40 0 0
    //         0 30 2 1
    //  fast : 0 20 2 1
    //  fast2: 1 20 2 1
    //  fast3: 1 10 2 1
    ikcp_nodelay(ktun->kcp, 0, 40, 0, 0);

    ikcp_wndsize(ktun->kcp, 2048, 2048);

    // TODO: set minrto
    hmutex_init(&ktun->kmux);
    ktun->ktid = hthread_create(kcp_update_thread, ktun);

    return ktun;
}

void release_kcp_tunnel(tor_t* ktun)
{
    ikcp_release(ktun->kcp);

    // pthread_cancel(ktun->ktid);
    // pthread_join(ktun->ktid, NULL);

    free(ktun);
}

void kcp_set_ctx(tor_t* tun, void* ctx)
{
    tun->ctx = ctx;
}

void* kcp_get_ctx(tor_t* tun)
{
    return tun->ctx;
}

void kcp_set_heartbeat(tor_t* tunnel, int interval_ms, kcp_send_heartbeat_fn fn)
{
    tunnel->heartbeat_interval = interval_ms;
    tunnel->heartbeat_fn = fn;
}

io_t* kcp_getio(tor_t* tun)
{
    return tun->io;
}
/**
 * @brief 通过cid 释放io持有的cm中的通道信息。
 *
 * @param tun
 * @return int
 */
int kcp_close(tor_t* tun)
{
    tun->stop = 1;
    io_del_tunnel(tun->io, tun->cid);
    return 0;
}
/******************************************************************************/
