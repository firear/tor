#ifndef __IO_H__
#define __IO_H__

#include <string.h>

typedef struct io_s {

    int (*recvfrom)(struct io_s* io, void* buffer, size_t length, void* addr);

    int (*sendto)(struct io_s* io, const void* data, size_t datalen, const void* addr);
} io_t;

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#endif