#include "kcp_tunnel.h"
#include "ikcp.h"
#include <pthread.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/******************************************************************************/

typedef struct kcp_tunnel_s {
    RECV_CB recv_cb;
    void* recv_arg;

    pthread_t ktid;
    pthread_mutex_t kmux;

    void* kcp;
    io_t* io;
} kcp_tunnel_t;

#define KCP_CONV 0x12345678

static unsigned int gettick_ms()
{
#ifdef _WIN32
    return GetTickCount();
#elif HAVE_CLOCK_GETTIME
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
#endif
}

/******************************************************************************/

int kcp_send(kcp_tunnel_t* ktun, const void* buf, int len)
{
    int retv;

    pthread_mutex_lock(&ktun->kmux);
    retv = ikcp_send(ktun->kcp, buf, len);
    int current = gettick_ms();
    ikcp_update(ktun->kcp, current);
    pthread_mutex_unlock(&ktun->kmux);
    return retv;
}

void kcp_input(kcp_tunnel_t* ktun, const void* buf, int len)
{
    char rbuf[1536];

    pthread_mutex_lock(&ktun->kmux);
    ikcp_input(ktun->kcp, buf, len);
    pthread_mutex_unlock(&ktun->kmux);

    while (1) {
        pthread_mutex_lock(&ktun->kmux);
        len = ikcp_recv(ktun->kcp, rbuf, sizeof(rbuf));
        pthread_mutex_unlock(&ktun->kmux);
        if (len < 0) {
            break;
        }

        ktun->recv_cb(rbuf, len, ktun->recv_arg);
    }
}

/******************************************************************************/

static int kcp_output(const char* buf, int len, void* kcp, void* user)
{
    kcp_tunnel_t* ktun = (kcp_tunnel_t*)user;

    return ktun->io->sendto(ktun->io, buf, len, NULL);
}

static void* kcp_update_thread(void* arg)
{
    kcp_tunnel_t* ktun = (kcp_tunnel_t*)arg;
    int current, next, len;
    char rbuf[1536];

    while (1) {
        pthread_testcancel();
        pthread_mutex_lock(&ktun->kmux);
        while (1) {
            len = ikcp_recv(ktun->kcp, rbuf, sizeof(rbuf));
            if (len < 0) {
                break;
            }
            ktun->recv_cb(rbuf, len, ktun->recv_arg);
        }

        current = gettick_ms();
        ikcp_update(ktun->kcp, current);
        next = ikcp_check(ktun->kcp, current);
        pthread_mutex_unlock(&ktun->kmux);

        next -= current;
        if (next > 0) {
            usleep(next * 1000);
        }
    }

    return NULL;
}

/******************************************************************************/

kcp_tunnel_t* new_kcp_tunnel(io_t* io, int mtu, RECV_CB recv_cb, void* arg)
{
    kcp_tunnel_t* ktun;

    ktun = (kcp_tunnel_t*)malloc(sizeof(kcp_tunnel_t));
    memset(ktun, 0, sizeof(kcp_tunnel_t));

    ktun->io = io;
    ktun->recv_cb = recv_cb;
    ktun->recv_arg = arg;

    ktun->kcp = ikcp_create(KCP_CONV, ktun);

    ikcp_setoutput(ktun->kcp, kcp_output);
    ikcp_setmtu(ktun->kcp, mtu + 8); // data + stream_header

    // normal: 0 40 0 0
    //         0 30 2 1
    //  fast : 0 20 2 1
    //  fast2: 1 20 2 1
    //  fast3: 1 10 2 1
    ikcp_nodelay(ktun->kcp, 1, 20, 2, 1);

    ikcp_wndsize(ktun->kcp, 2048, 2048);

    // TODO: set minrto

    pthread_mutex_init(&ktun->kmux, NULL);
    pthread_create(&ktun->ktid, NULL, kcp_update_thread, ktun);

    return ktun;
}

void close_kcp_tunnel(kcp_tunnel_t* ktun)
{
    ikcp_release(ktun->kcp);

    pthread_cancel(ktun->ktid);
    pthread_join(ktun->ktid, NULL);

    free(ktun);
}

/******************************************************************************/
