#ifndef __IO_RAW_H__
#define __IO_RAW_H__

#include "io.h"
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef enum RAWMODE {
    RAWMODE_UNSET,
    RAWMODE_ICMP,
    RAWMODE_FUDP,
    RAWMODE_FTCP,
} RAWMODE;

/**
 * @brief
 *
 * @param mode
 * @param devname
 * @param serverip 目的IP地址
 * @param server_port 目的端口，ICMP无意义，FUDP/FTCP模式下若为0则从1开始尝试直到连接建立成功。
 * @param cb
 * @return io_t*
 */
io_t* initraw_client(RAWMODE mode, const char* devname, const char* serverip, const uint16_t server_port, CB_CONN cb);

/**
 * @brief
 *
 * @param mode
 * @param devname 网卡设备
 * @param serverip 无意义
 * @param server_port 无意义
 * @param cb
 * @return io_t*
 */
io_t* initraw_server(RAWMODE mode, const char* devname, const char* serverip, const uint16_t server_port, CB_CONN cb);

int rawio_conn(io_t *io, const char *serverip, const uint16_t server_port, CB_CONN cb);

#ifdef __cplusplus
}
#endif
#endif //__IO_RAW_H__