

#include "io.h"
#include <stdint.h>

typedef struct io_udp_s {
    io_t io;

    int client_fd;
    //     int a;
    // int server_fd;
} io_udp_t;

io_udp_t* initudpserver(uint16_t server_port);
io_udp_t* initudpclient(const char* serverip, const uint16_t server_port);
