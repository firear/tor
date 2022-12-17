#ifndef __IO_UDP_H__
#define __IO_UDP_H__

#include "io.h"
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

io_t* initudpserver(const char* serverip, uint16_t server_port, CB_CONN cb);
io_t* initudpclient(const char* serverip, const uint16_t server_port, CB_CONN cb);

#ifdef __cplusplus
}
#endif
#endif //__IO_UDP_H__