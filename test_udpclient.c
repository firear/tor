#include "hloop.h"
#include "tor/io_udp.h"
#include "tor/kcp_tunnel.h"

kcp_tunnel_t* g_tun;

void recv_cb(const void* buf, int len, void* user)
{
    printf("%s\n", (char *)buf);
}

void startclient()
{
    io_udp_t* cio = initudpclient("127.0.0.1", 9999);
    g_tun = new_kcp_tunnel((io_t*)cio, 1000, recv_cb, NULL);
}

void on_stdin(hio_t* io, void* buf, int buflen)
{
    kcp_send(g_tun, buf, buflen);
}

int main(int argc, char const* argv[])
{
    const char* host = argv[1];
    int port = atoi(argv[2]);

    hloop_t* loop = hloop_new(HLOOP_FLAG_QUIT_WHEN_NO_ACTIVE_EVENTS);

    // stdin use default readbuf
    hio_t* stdinio = hread(loop, STDIN_FILENO, NULL, 0, on_stdin);

    if (stdinio == NULL) {
        return -20;
    }

    startclient();

    printf("begin loop\n");
    hloop_run(loop);
    printf("loop end\n");
    hloop_free(&loop);

    return 0;
}
