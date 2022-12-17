#include "tor/io_raw.h"
#include "tor/tor.h"

#include "debug.h"

tor_t* g_tun = NULL;

void recv_cb(tor_t* tun, const void* buf, int len)
{
    LOGV("%s :%.*s\n", __func__, len, (char*)buf);
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
        if (strncmp(buf, "close", 5) == 0) {
            printf("call hio_close\n");
            kcp_close(g_tun);
            continue;
        }
        if (g_tun) {
            kcp_send(g_tun, buf, buflen);
        }
    }
    return NULL;
}

/**
 * @brief
 * ./test_tor s enp3s0 icmp/fudp/ftcp
 * ./test_tor c enp3s0 icmp/fudp/ftcp 192.168.0.2 9999
 *
 * @param argc
 * @param argv
 * @return int
 */
int main(int argc, char const* argv[])
{
    LOGV("init");
    pthread_t tid;
    pthread_create(&tid, NULL, readstdin, NULL);

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
            io = initraw_server(mode, devname, NULL, sport, on_connected);
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
