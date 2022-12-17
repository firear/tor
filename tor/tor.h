#ifndef __KCP_TUNNEL_H__
#define __KCP_TUNNEL_H__

#include "hsocket.h"
#include <stdint.h>

typedef struct io_s io_t;
typedef struct kcp_tunnel_s tor_t;

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

typedef struct addrinfo_s {
    uint8_t eth_peer[ETH_ALEN];
    uint8_t eth_local[ETH_ALEN];
    sockaddr_u sockaddr_local;
    sockaddr_u sockaddr_peer;
    uint32_t tcp_seq;
    uint32_t tcp_ack; // recv ack
    uint32_t nxt_ack; // seq+plen
    uint8_t is_serveraddr; //
} addrinfo_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 初始化资源
 *
 * @param io
 * @param cid
 * @param mtu
 * @return kcp_tunnel_t*
 */
tor_t* new_kcp_tunnel(io_t* io, int cid, int mtu);
/**
 * @brief 释放资源
 *
 * @param tunnel
 */
void release_kcp_tunnel(tor_t* tunnel);

void kcp_update(tor_t* tunnel);

io_t* kcp_getio(tor_t* tun);

// 接收
void kcp_input(tor_t* tunnel, addrinfo_t* addr, const void* buf, int len);

////////////////////////////////////////////////////////////

typedef void (*RECV_CB)(tor_t* tunnel, const void* buf, int len);
/**
 * @brief 通过该接口设置接收数据回调
 *
 * @param tunnel
 * @param recv_cb
 */
void kcp_set_recvcb(tor_t* tunnel, RECV_CB recv_cb);

// 调用该函数外发，内部回调rawio的sendto
int kcp_send(tor_t* tunnel, const void* buf, int len);

/**
 * @brief icmp server 端难以主动发送数据，可通过心跳激活通道。
 *
 */
typedef void (*kcp_send_heartbeat_fn)(tor_t* tunnel);
void kcp_set_heartbeat(tor_t* tunnel, int interval_ms, kcp_send_heartbeat_fn fn);

/**
 * @brief 关闭通道
 *
 * @param tun
 * @return int
 */
int kcp_close(tor_t* tun);

void kcp_set_ctx(tor_t* tun, void* ctx);
void* kcp_get_ctx(tor_t* tun);

#ifdef __cplusplus
}
#endif

#endif
