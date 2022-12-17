#include "crc32.h"
#include <stdio.h>

uint8_t init = 0;
uint32_t CRC32_TB[256];

void init_table()
{
    if (!init) {
        int i, j;
        uint32_t crc;
        for (i = 0; i < 256; i++) {
            crc = i;
            for (j = 0; j < 8; j++) {
                if (crc & 1) {
                    crc = (crc >> 1) ^ 0xEDB88320;
                } else {
                    crc = crc >> 1;
                }
            }
            CRC32_TB[i] = crc;
        }
        init = 1;
    }
}

// crc32实现函数
uint32_t crc32(const void* tmp, size_t len)
{
    const uint8_t* buf = (const uint8_t*)tmp;
    uint32_t ret = 0xFFFFFFFF;

    init_table();

    for (size_t i = 0; i < len; i++) {
        ret = CRC32_TB[((ret & 0xFF) ^ buf[i])] ^ (ret >> 8);
    }
    ret = ~ret;
    return ret;
}
