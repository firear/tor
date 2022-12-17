#include "io_raw.h"
#include "debug.h"
#include "ethertype.h"
#if __linux
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netpacket/packet.h> //struct sockaddr_ll
#endif

#include <pcap/pcap.h>

typedef struct rawio_s {
    io_t io;

    RAWMODE mode;
    uint8_t isserver;

    CB_CONN __on_connected;
    CB_CONN __on_accepted;

    union {
        struct { // FUDP
            int udp_sockfd;
        };
        struct { // FTCP
            int tcp_sockfd;
        };
        // for icmp
        struct {
            uint16_t icmp_id;
            uint16_t icmp_seq;
        };
    };

    // for pcap
    char devname[16];
    pcap_t* pcaphandler;
    char* filterstr; // pcap filter

} rawio_t;

#define ICMP_INFORMATION_REQ 15
#define ICMP_INFORMATION_RSP 16

/******************************************************************************/

typedef struct eth_hdr_s {
    uint8_t dst[ETH_ALEN];
    uint8_t src[ETH_ALEN];
    uint16_t type;
} eth_hdr_t;

typedef struct ipv4_hdr_s {
#if BIGENDINA
    uint8_t version : 4; // length of header
    uint8_t h_len : 4; // Version of IP
#else
    uint8_t h_len : 4; // length of header
    uint8_t version : 4; // Version of IP
#endif
    uint8_t tos; // Type of service
    uint16_t total_len; // total length of the packet

    uint16_t ident; // unique identifier
    uint16_t frag_and_flags; // flags

    uint8_t ttl; // ttl
    uint8_t proto; // protocol(TCP ,UDP etc)
    uint16_t checksum; // IP checksum

    uint8_t src_ip[4];
    uint8_t dst_ip[4];
} ipv4_hdr_t;

typedef struct ipv6_hdr_s {
    union {
        struct ip6_hdrctl {
            uint32_t ip6_un1_flow; /* 20 bits of flow-ID */
            uint16_t ip6_un1_plen; /* payload length */
            uint8_t ip6_un1_nxt; /* next header */
            uint8_t ip6_un1_hlim; /* hop limit */
        } ip6_un1;
        uint8_t ip6_un2_vfc; /* 4 bits version, top 4 bits class */
    } ip6_ctlun;
    uint8_t src_ip[16]; /* source address */
    uint8_t dst_ip[16]; /* destination address */
} ipv6_hdr_t;

typedef struct icmp_hdr_s { // same as imcpv6
    uint8_t type;
    uint8_t code;
    uint16_t cksum;
    uint16_t id;
    uint16_t seq;
    uint8_t data[0];
} icmp_hdr_t;

typedef struct udp_hdr_s {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t total_len;
    uint16_t cksum;
    uint8_t data[0];
} udp_hdr_t;

typedef struct tcp_hdr_s {
    uint16_t th_sport;
    uint16_t th_dport;
    uint32_t th_seq;
    uint32_t th_ack;
    union {
        struct {
#if BIGENDINA
            uint16_t doff : 4;
            uint16_t rev1 : 3;
            uint16_t acc_ecn : 1;
            uint16_t cwr : 1; // Congestion Window Reduced
            uint16_t ecn_echo : 1;
            uint16_t urg : 1;
            uint16_t ack : 1;
            uint16_t psh : 1;
            uint16_t rst : 1;
            uint16_t syn : 1;
            uint16_t fin : 1;
#else
            uint16_t acc_ecn : 1;
            uint16_t rev1 : 3;
            uint16_t doff : 4;
            uint16_t fin : 1;
            uint16_t syn : 1;
            uint16_t rst : 1;
            uint16_t psh : 1;
            uint16_t ack : 1;
            uint16_t urg : 1;
            uint16_t ecn_echo : 1;
            uint16_t cwr : 1; // Congestion Window Reduced
#endif
        };
        uint16_t th_off_flags;
    };
    uint16_t th_win;
    uint16_t th_sum;
    uint16_t th_urp;
    uint8_t data[0];
} tcp_hdr_t;

// for checksum
typedef struct cksum_header_s {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t length;
} cksum_header_t;

typedef struct cksum_header6_s {
    struct in6_addr src;
    struct in6_addr dst;
    uint32_t length;
    uint16_t placeholder1;
    uint8_t placeholder2;
    uint8_t next_header;
} cksum_header6_t;

#ifdef _WIN32
#include "Packet32.h"
#include <Ntddndis.h>
#include <tchar.h>
BOOL LoadNpcapDlls()
{
    _TCHAR npcap_dir[512];
    UINT len;
    len = GetSystemDirectory(npcap_dir, 480);
    if (!len) {
        fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
        return FALSE;
    }
    _tcscat_s(npcap_dir, 512, _T("\\Npcap"));
    if (SetDllDirectory(npcap_dir) == 0) {
        fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
        return FALSE;
    }
    return TRUE;
}
#endif

void __dumpaddr(struct sockaddr* addr)
{
    char buf[64];
    if (addr) {
#if __linux
        if (addr->sa_family == AF_PACKET) {
            struct sockaddr_ll* a = (struct sockaddr_ll*)addr;
            sprintf(buf, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", a->sll_addr[0], a->sll_addr[1], a->sll_addr[2], a->sll_addr[3], a->sll_addr[4], a->sll_addr[5]);
        } else
#endif
            if (addr->sa_family == AF_INET) {
            struct sockaddr_in* a = (struct sockaddr_in*)addr;
            inet_ntop(AF_INET, &a->sin_addr, buf, sizeof(struct sockaddr_in));
        } else {
            printf("%d\n", addr->sa_family);
        }
    }

    printf("%s\n", buf);
}

void enumdev()
{
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int i = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    /* Retrieve the device list on the local machine */
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    /* Print the list */
    for (d = alldevs; d; d = d->next) {
        printf("================%d. %s\n", ++i, d->name);
        for (struct pcap_addr* addr = d->addresses; addr; addr = addr->next) {
            printf("addr \n");
            __dumpaddr(addr->addr);
            printf("netmask \n");
            __dumpaddr(addr->netmask);
            printf("broadaddr \n");
            __dumpaddr(addr->broadaddr);
            printf("dstaddr \n");
            __dumpaddr(addr->dstaddr);
        }
        printf("addr end===============\n");
    }

    if (i == 0) {
        printf("\nNo interfaces found! Make sure Npcap is installed.\n");
    }
    pcap_freealldevs(alldevs);
}

unsigned short checksum(unsigned short* buffer, size_t size)
{
    unsigned int cksum = 0;
    while (1 < size) {
        cksum += *buffer++;
        size -= sizeof(unsigned short);
    }
    if (0 < size) {
#if BIGENDIAN
        cksum += *(uint8_t*)buffer << 8;
#else
        cksum += *(uint8_t*)buffer;
#endif
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (unsigned short)(~cksum);
}

int __dealpacket(rawio_t* rawio, struct pcap_pkthdr* pkt_header, const uint8_t* pkt_data, void* data, size_t datalen, addrinfo_t* addr)
{
    int ret = -1;
    do {
        // ETH
        eth_hdr_t* eh = (eth_hdr_t*)pkt_data;
        if (pkt_header->len > sizeof(eth_hdr_t)) {
            memcpy(addr->eth_local, eh->dst, sizeof(addr->eth_local));
            memcpy(addr->eth_peer, eh->src, sizeof(addr->eth_peer));
            //
            pkt_header->len -= sizeof(eth_hdr_t);
            pkt_data += sizeof(eth_hdr_t);
        } else {
            break;
        }
        // IP
        uint8_t nxtpro = 0;
        uint16_t payloadlen = 0;
        if (eh->type == ETHERTYPE_IP) { // ipv4
            if (pkt_header->len < sizeof(ipv4_hdr_t)) {
                break;
            }
            ipv4_hdr_t* iph = (ipv4_hdr_t*)pkt_data;
            addr->sockaddr_local.sin.sin_family = AF_INET;
            memcpy(&addr->sockaddr_local.sin.sin_addr, iph->dst_ip, sizeof(addr->sockaddr_local.sin.sin_addr));

            addr->sockaddr_peer.sin.sin_family = AF_INET;
            memcpy(&addr->sockaddr_peer.sin.sin_addr, iph->src_ip, sizeof(addr->sockaddr_peer.sin.sin_addr));
            nxtpro = iph->proto;
            payloadlen = ntohs(iph->total_len) - (iph->h_len << 2);

            pkt_header->len -= iph->h_len << 2;
            pkt_data += iph->h_len << 2;
        } else if (eh->type == ETHERTYPE_IPV6) {
            if (pkt_header->len < sizeof(ipv6_hdr_t)) {
                break;
            }
            ipv6_hdr_t* iph = (ipv6_hdr_t*)pkt_data;
            addr->sockaddr_local.sin.sin_family = AF_INET6;
            memcpy(&addr->sockaddr_local.sin6.sin6_addr, iph->dst_ip, sizeof(addr->sockaddr_local.sin6.sin6_addr));

            addr->sockaddr_peer.sin.sin_family = AF_INET6;
            memcpy(&addr->sockaddr_peer.sin6.sin6_addr, iph->src_ip, sizeof(addr->sockaddr_peer.sin6.sin6_addr));

            nxtpro = iph->ip6_ctlun.ip6_un1.ip6_un1_nxt;
            payloadlen = iph->ip6_ctlun.ip6_un1.ip6_un1_plen;

            pkt_header->len -= sizeof(ipv6_hdr_t);
            pkt_data += sizeof(ipv6_hdr_t);
        } else {
            LOGE("not handled type %x", eh->type);
            break;
        }
        switch (rawio->mode) {
        case RAWMODE_ICMP:
            // ICMP
            if (nxtpro == IPPROTO_ICMP || nxtpro == IPPROTO_ICMPV6) {
                icmp_hdr_t* icmp = (icmp_hdr_t*)pkt_data;
                if (icmp->type == ICMP_INFORMATION_REQ || icmp->type == ICMP_INFORMATION_RSP) {
                    pkt_header->len -= sizeof(icmp_hdr_t);
                    memcpy(data, icmp->data, pkt_header->len);
                    ret = pkt_header->len;
                }else{
                    ret = 0;
                    LOGI("ignore other icmp");
                }
            } else {
                LOGE("expect icmp but %d", nxtpro);
            }
            break;
        case RAWMODE_FUDP:
            if (nxtpro == IPPROTO_UDP) {
                udp_hdr_t* udp = (udp_hdr_t*)pkt_data;
                if (addr->sockaddr_local.sin.sin_family == AF_INET) {
                    addr->sockaddr_local.sin.sin_port = udp->dst_port;
                    addr->sockaddr_peer.sin.sin_port = udp->src_port;
                } else {
                    addr->sockaddr_local.sin6.sin6_port = udp->dst_port;
                    addr->sockaddr_peer.sin6.sin6_port = udp->src_port;
                }

                pkt_header->len -= sizeof(udp_hdr_t);
                memcpy(data, udp->data, pkt_header->len);
                ret = pkt_header->len;
            } else {
                LOGE("expect udp but %d", nxtpro);
            }
            break;
        case RAWMODE_FTCP:
            if (nxtpro == IPPROTO_TCP) {
                tcp_hdr_t* tcp = (tcp_hdr_t*)pkt_data;
                if (addr->sockaddr_local.sin.sin_family == AF_INET) {
                    addr->sockaddr_local.sin.sin_port = tcp->th_dport;
                    addr->sockaddr_peer.sin.sin_port = tcp->th_sport;
                } else {
                    addr->sockaddr_local.sin6.sin6_port = tcp->th_dport;
                    addr->sockaddr_peer.sin6.sin6_port = tcp->th_sport;
                }

                uint16_t hlen = tcp->doff << 2;
                pkt_header->len -= hlen;
                pkt_data += hlen;
                memcpy(data, pkt_data, pkt_header->len);
                ret = pkt_header->len;
                addr->nxt_ack = ntohl(tcp->th_seq) + ret;
            } else {
                LOGE("expect tcp but %d", nxtpro);
            }
            break;
        default:
            break;
        }
    } while (0);
    return ret;
}

int closeraw(struct io_s* io)
{
    // TODO
    rawio_t* rio = (rawio_t*)io;
    pcap_close(rio->pcaphandler);
    if (rio->mode == RAWMODE_FUDP && rio->udp_sockfd >= 0) {
        close(rio->udp_sockfd);
    } else if (rio->mode == RAWMODE_FTCP && rio->tcp_sockfd >= 0) {
        close(rio->tcp_sockfd);
    }

    free(rio);
    return 0;
}

int recvraw(struct io_s* io, void* data, size_t datalen, addrinfo_t* addr)
{
    rawio_t* rawio = (rawio_t*)io;
    struct pcap_pkthdr* pkt_header;
    const u_char* pkt_data;
    int ret = pcap_next_ex(rawio->pcaphandler, &pkt_header, &pkt_data);
    if (ret > 0 && pkt_header->len > 0) {
        LOGI("%s: rawlen %d", __func__, pkt_header->len);
        ret = __dealpacket(rawio, pkt_header, pkt_data, data, datalen, addr);
        LOGI("%s: datalen %d", __func__, ret);
    }

    return ret;
}

static int __pack_iph(struct io_s* io, uint8_t* pBuf, size_t datalen, uint8_t proto, const addrinfo_t* addr)
{
    ipv4_hdr_t* pIph = (ipv4_hdr_t*)pBuf;
    pIph->h_len = 0x5;
    pIph->version = 0x4;
    pIph->tos = 0;

    pIph->total_len = htons(sizeof(ipv4_hdr_t) + datalen);

    pIph->ident = rand();
    pIph->frag_and_flags = 0x40;
    pIph->ttl = 0x40;
    pIph->proto = proto;
    pIph->checksum = 0;
    memcpy(&pIph->src_ip, &addr->sockaddr_local.sin.sin_addr, 4);
    memcpy(&pIph->dst_ip, &addr->sockaddr_peer.sin.sin_addr, 4);
    pIph->checksum = checksum((unsigned short*)pIph, sizeof(ipv4_hdr_t));
    return sizeof(ipv4_hdr_t);
}

static int __pack_eth_ipv4(struct io_s* io, uint8_t* buf, const addrinfo_t* addr)
{
    eth_hdr_t* e = (eth_hdr_t*)buf;
    memcpy(e->dst, addr->eth_peer, sizeof(e->dst));
    memcpy(e->src, addr->eth_local, sizeof(e->src));
    e->type = 0x0008;
    return sizeof(eth_hdr_t);
}

static int __pack_icmp(rawio_t* rio, uint8_t* buf, const void* data, size_t datalen, uint8_t isserveraddr)
{
    icmp_hdr_t* icmp = (icmp_hdr_t*)buf;
    LOGI("%s isserveraddr:%d", __func__, isserveraddr);
    // if (rio->isserver) {
    if (!isserveraddr) {
        icmp->type = ICMP_INFORMATION_RSP;
    } else {
        icmp->type = ICMP_INFORMATION_REQ;
    }

    icmp->code = 0;
    icmp->cksum = 0;
    icmp->id = 0;
    icmp->seq = 0;
    memcpy(icmp->data, data, datalen);

    icmp->cksum = checksum((unsigned short*)icmp, sizeof(icmp_hdr_t) + datalen);
    return sizeof(icmp_hdr_t) + datalen;
}

static uint16_t __chcksum(uint8_t prototype, uint8_t* buf, uint16_t buflen, const addrinfo_t* addr)
{
    char backupdata[sizeof(cksum_header_t)];
    cksum_header_t* spbuffer = (cksum_header_t*)(buf - sizeof(cksum_header_t));
    memcpy(backupdata, spbuffer, sizeof(cksum_header_t));

    spbuffer->source_address = addr->sockaddr_local.sin.sin_addr.s_addr;
    spbuffer->dest_address = addr->sockaddr_peer.sin.sin_addr.s_addr;
    spbuffer->placeholder = 0;
    spbuffer->protocol = prototype;
    spbuffer->length = htons(buflen);

    uint16_t cksum = checksum((unsigned short*)spbuffer, buflen + sizeof(cksum_header_t));
    memcpy(spbuffer, backupdata, sizeof(cksum_header_t));
    return cksum;
}

static int __pack_udp(rawio_t* rio, uint8_t* buf, const void* data, size_t datalen, const addrinfo_t* addr)
{
    uint16_t totallen = sizeof(udp_hdr_t) + datalen;
    udp_hdr_t* uh = (udp_hdr_t*)buf;
    uh->src_port = addr->sockaddr_local.sa.sa_family == AF_INET ? addr->sockaddr_local.sin.sin_port : addr->sockaddr_local.sin6.sin6_port;
    uh->dst_port = addr->sockaddr_peer.sa.sa_family == AF_INET ? addr->sockaddr_peer.sin.sin_port : addr->sockaddr_peer.sin6.sin6_port;
    uh->cksum = 0;
    uh->total_len = htons(totallen);
    if (datalen > 0) {
        memcpy(uh->data, data, datalen);
    }
    uh->cksum = __chcksum(IPPROTO_UDP, buf, totallen, addr);
    return totallen;
}

static int __pack_tcp(rawio_t* rio, uint8_t* buf, const void* data, size_t datalen, const addrinfo_t* addr)
{
    addrinfo_t* seqctx = (addrinfo_t*)addr;
    io_head_t* datah = (io_head_t*)data;
    uint16_t totallen = sizeof(tcp_hdr_t) + datalen;
    tcp_hdr_t* th = (tcp_hdr_t*)buf;
    th->th_sport = addr->sockaddr_local.sa.sa_family == AF_INET ? addr->sockaddr_local.sin.sin_port : addr->sockaddr_local.sin6.sin6_port;
    th->th_dport = addr->sockaddr_peer.sa.sa_family == AF_INET ? addr->sockaddr_peer.sin.sin_port : addr->sockaddr_peer.sin6.sin6_port;
    th->th_seq = htonl(addr->tcp_seq);
    th->th_ack = htonl(addr->tcp_ack);

    th->th_off_flags = 0;
    th->doff = sizeof(tcp_hdr_t) >> 2;

    // if (rio->isserver) {
    //     th->ack = 1;
    // } else {
    //     th->syn = 1;
    // }
    th->syn = !!(datah->type & DTYPE_SYN);
    th->ack = !!(datah->type & DTYPE_ACK);
    th->psh = !!(datah->type & DTYPE_PSH);

    th->th_win = htons(1500);
    th->th_sum = 0;
    th->th_urp = 0;
    if (datalen > 0) {
        memcpy(th->data, data, datalen);
    }
    th->th_sum = __chcksum(IPPROTO_TCP, buf, totallen, addr);

    // after send
    seqctx->tcp_seq += datalen;
    if (th->syn) {
        seqctx->tcp_seq++;
    }
    // end
    return totallen;
}

int sendraw(struct io_s* io, const void* data, size_t datalen, const addrinfo_t* addr)
{
    int ret = 0;
    LOGI("%s: datalen %d", __func__, datalen);
    rawio_t* rawio = (rawio_t*)io;
    uint8_t pBuf[1800];
    int pos = 0;

    pos += __pack_eth_ipv4(io, pBuf, addr);
    switch (rawio->mode) {
    case RAWMODE_ICMP:
        pos += __pack_iph(io, pBuf + pos, datalen + sizeof(icmp_hdr_t), IPPROTO_ICMP, addr);
        pos += __pack_icmp(rawio, pBuf + pos, data, datalen, addr->is_serveraddr);
        break;
    case RAWMODE_FUDP:
        pos += __pack_iph(io, pBuf + pos, datalen + sizeof(udp_hdr_t), IPPROTO_UDP, addr);
        pos += __pack_udp(rawio, pBuf + pos, data, datalen, addr);
        break;
    case RAWMODE_FTCP:
        pos += __pack_iph(io, pBuf + pos, datalen + sizeof(tcp_hdr_t), IPPROTO_TCP, addr);
        pos += __pack_tcp(rawio, pBuf + pos, data, datalen, addr);
        break;
    default:
        break;
    }
    ret = pcap_inject(rawio->pcaphandler, pBuf, pos);
    return ret;
}

static int setfilter(rawio_t* io, const char* filter)
{
    LOGI("%s:%s", __func__, filter);
    int ret = 0;
    struct bpf_program fp;

    bpf_u_int32 mask = 0;
#if 0
    bpf_u_int32 net;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_lookupnet(io->devname, &net, &mask, errbuf) == -1) {
        LOGE("pcap_lookupnet %s", errbuf);
        net = 0;
        mask = 0;
        ret = -1;
    }
#endif
    /* compile the filter */
    if (pcap_compile(io->pcaphandler, &fp, filter, 1, mask) < 0) {
        ret = -1;
    }
    /* set the filter */
    if (pcap_setfilter(io->pcaphandler, &fp) < 0) {
        ret = -1;
    }
    return ret;
}

int __testsend(rawio_t* io)
{
    // memcpy(io->io.addr.eth_local, "\x00\x1b\x21\x39\xe1\x05", 6);
    // memcpy(io->io.addr.eth_peer, "\x80\xfb\x06\xb1\x65\x13", 6);
    // memcpy(&io->io.addr.sockaddr_local.sin.sin_addr, "\xc0\xa9\x32\x01", 4);
    // memcpy(&io->io.addr.sockaddr_peer.sin.sin_addr, "\x17\xec\x42\xcd", 4);

    return sendraw((io_t*)io, "aabbccdd", 8, &io->io.addr);
}

rawio_t* __opendev(const char* devname)
{
    // enumdev();
    char errbuf[PCAP_ERRBUF_SIZE];

    rawio_t* io = calloc(1, sizeof(rawio_t));
    strcpy(io->devname, devname);
#if _WIN32
    /* Load Npcap and its functions. */
    if (!LoadNpcapDlls()) {
        LOGF("no npcap");
    }
    io->pcaphandler = pcap_open(devname, 65536, 0, 100, NULL, errbuf);
#else
    io->pcaphandler = pcap_open_live(devname, 65536, 0, 100, errbuf);
#endif
    if (io->pcaphandler == NULL) {
        LOGE("Unable to open the adapter.%s", errbuf);
        /* Free the device list */
        free(io);
        io = NULL;
    } else {
        LOGI("listening on %s...", devname);
        // pcap_setnonblock(io->pcaphandler, 1, errbuf);
        io->io.sendtoraw = sendraw;
        io->io.recvfromraw = recvraw;
        io->io.closeraw = closeraw;
        cm_init(&io->io.cm);
    }
    return io;
}

void __filladdr(const struct sockaddr* addr, addrinfo_t* addrinfo)
{
    char buf[64];
    if (addr) {
#if __linux
        if (addr->sa_family == AF_PACKET) {
            struct sockaddr_ll* a = (struct sockaddr_ll*)addr;
            memcpy(addrinfo->eth_local, a->sll_addr, a->sll_halen);
            sprintf(buf, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", a->sll_addr[0], a->sll_addr[1], a->sll_addr[2], a->sll_addr[3], a->sll_addr[4], a->sll_addr[5]);
        } else
#endif
            if (addr->sa_family == AF_INET) {
            struct sockaddr_in* a = (struct sockaddr_in*)addr;
            inet_ntop(AF_INET, &a->sin_addr, buf, sizeof(struct sockaddr_in));
            addrinfo->sockaddr_local.sin = *a;
        } else {
            LOGW("%d\n", addr->sa_family);
        }
    }

    LOGI("%s:%s", __func__, buf);
}

int __bindsocket(rawio_t* rio, int type)
{
    int fd = socket(AF_INET, type, 0); // AF_INET:IPV4;SOCK_DGRAM:UDP
    if (fd >= 0) {
        if (bind(fd, (struct sockaddr*)&rio->io.addr.sockaddr_local, sizeof(struct sockaddr_in)) == 0) {
            socklen_t len;
            getsockname(fd, (struct sockaddr*)&rio->io.addr.sockaddr_local, &len);
        } else {
            LOGE("socket bind fail!");
        }
    } else {
        LOGE("create socket fail!");
    }
    return fd;
}

int __set_local_addr(rawio_t* rio, const char* devname)
{
    // TODO IPV6
    pcap_if_t* alldevs;
    pcap_if_t* d;
    char errbuf[PCAP_ERRBUF_SIZE];
    uint8_t found = 0;
    /* Retrieve the device list on the local machine */
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        LOGF("Error in pcap_findalldevs: %s\n", errbuf);
    }

    /* Print the list */
    for (d = alldevs; d; d = d->next) {
        if (!strcmp(d->name, devname)) {
            for (struct pcap_addr* addr = d->addresses; addr; addr = addr->next) {
                __filladdr(addr->addr, &rio->io.addr);
            }
            found = 1;
            break;
        }
    }

    if (found == 0) {
        LOGE("\nNo interfaces found! Make sure Npcap is installed.\n");
    }
    pcap_freealldevs(alldevs);
    if (rio->mode == RAWMODE_FUDP) {
        rio->udp_sockfd = __bindsocket(rio, SOCK_DGRAM);
    } else if (rio->mode == RAWMODE_FTCP) {
        rio->tcp_sockfd = __bindsocket(rio, SOCK_STREAM);
    }

    return 0;
}

int __setaddr(rawio_t* rio, const char* devname, const char* serverip, const uint16_t server_port)
{
    int ret = __set_local_addr(rio, devname);

    if (!rio->isserver) { // peer addr only needed by client mode
        rio->io.addr.sockaddr_peer.sin.sin_family = AF_INET;
        if (serverip) {
            inet_pton(AF_INET, serverip, &rio->io.addr.sockaddr_peer.sin.sin_addr);
        } else {
            LOGF("must set server ip");
        }
        rio->io.addr.sockaddr_peer.sin.sin_port = htons(server_port);
        memcpy(rio->io.addr.eth_peer, "\xff\xff\xff\xff\xff\xff", 6);
    }
    return ret;
}

char* __getFilter(rawio_t* io, const char* devname, const char* serverip, const uint16_t server_port)
{
    char* morefilter = NULL;
    char* bigfilter = "";
    switch (io->mode) {
    case RAWMODE_ICMP:
        bigfilter = "icmp";
        if (!io->isserver) {
            asprintf(&morefilter, "src host %s", serverip);
        }
        break;
    case RAWMODE_FUDP:
        bigfilter = "udp";
        if (!io->isserver) {
            asprintf(&morefilter, "src host %s", serverip);
        }
        break;
    case RAWMODE_FTCP:
        bigfilter = "tcp";
        if (io->isserver) {
            asprintf(&morefilter, "dst port %hu", server_port);
        } else {
            asprintf(&morefilter, "(src host %s and src port %hu)", serverip, server_port);
        }
        break;
    default:
        break;
    }
    if (io->filterstr) {
        if (morefilter) {
            char* temp;
            asprintf(&temp, "%s or %s", io->filterstr, morefilter);
            free(io->filterstr);
            io->filterstr = temp;
        }
    } else {
        io->filterstr = morefilter;
    }
    char* ret = NULL;
    if (io->filterstr) {
        asprintf(&ret, "%s and (%s)", bigfilter, io->filterstr);
    } else {
        ret = strdup(bigfilter);
    }

    return ret;
}

io_t* initraw_client(RAWMODE mode, const char* devname, const char* serverip, const uint16_t server_port, CB_CONN cb)
{
    rawio_t* io = __opendev(devname);
    if (io) {
        io->mode = mode;
        io->isserver = 0;
        __setaddr(io, devname, serverip, server_port);
        char* filter = __getFilter(io, devname, serverip, server_port);
        setfilter(io, filter);
        free(filter);

        // while (1) {
        //     __testsend(io);
        // }
        io_conn((io_t*)io, serverip, server_port, cb);
    }
    return (io_t*)io;
}

int rawio_conn(io_t* io, const char* serverip, const uint16_t server_port, CB_CONN cb)
{
    // 1. update filter
    rawio_t* origio = (rawio_t*)io;
    origio->isserver = 0;
    __setaddr(origio, origio->devname, serverip, server_port);
    char* filter = __getFilter(origio, origio->devname, serverip, server_port);
    setfilter(origio, filter);
    free(filter);
    io_conn((io_t*)origio, serverip, server_port, cb);
    return 0;
}

io_t* initraw_server(RAWMODE mode, const char* devname, const char* serverip, const uint16_t server_port, CB_CONN cb)
{
    rawio_t* io = __opendev(devname);
    if (io) {
        io->mode = mode;
        io->isserver = 1;
        __setaddr(io, devname, serverip, server_port);
        char* filter = __getFilter(io, devname, serverip, server_port);
        setfilter(io, filter);
        free(filter);
        io_accept((io_t*)io, cb);
    }
    return (io_t*)io;
}
