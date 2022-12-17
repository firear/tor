#include "tor/io_udp.h"
#include "tor/tor.h"

#include "debug.h"

tor_t* g_tun = NULL;

void recv_cb(tor_t *tun, const void* buf, int len)
{
    LOGV("%s :%s\n", __func__, (char*)buf);
}

void on_connected(tor_t* tun)
{
    LOGI("%s %p", __func__, tun);
    g_tun = tun;
    kcp_set_recvcb(tun, recv_cb);
}

void* readstdin(void* p)
{
    char buf[1500];
    while (1) {
        int buflen = read(STDIN_FILENO, buf, sizeof(buf));
        if (g_tun) {
            kcp_send(g_tun, buf, buflen);
        }
    }
    return NULL;
}

int main(int argc, char const* argv[])
{
    LOGV("init");
    pthread_t tid;
    pthread_create(&tid, NULL, readstdin, NULL);
    const char* addr = "127.0.0.1";
    if (argc > 1) {
        addr = argv[1];
    }
    io_t* cio = initudpclient(addr, 9999, on_connected);

    io_startloop(cio);

    return 0;
}
