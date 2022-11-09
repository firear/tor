#ifndef __KCP_TUNNEL_H__
#define __KCP_TUNNEL_H__

#include "io.h"

typedef struct kcp_tunnel_s kcp_tunnel_t;

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*RECV_CB)(const void* buf, int len, void* user);

kcp_tunnel_t* new_kcp_tunnel(io_t* io, int mtu, RECV_CB recv_cb, void* arg);

void close_kcp_tunnel(kcp_tunnel_t* tunnel);

// 调用该函数外发，内部回调rawio的sendto
int kcp_send(kcp_tunnel_t* tunnel, const void* buf, int len);

// 接收
//void kcp_input(kcp_tunnel_t* tunnel, const void* buf, int len);

#ifdef __cplusplus
}
#endif

#endif
