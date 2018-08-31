#ifndef _SWAP_ENDIAN_H
#define _SWAP_ENDIAN_H

#include <pcap.h>

u_int16_t swap_endian_16(u_int16_t value);

u_int32_t swap_endian_32(u_int32_t value);

u_int64_t swap_endian_64(u_int64_t value);

u_int8_t is_little_endian();

u_int16_t be2local16(u_int16_t value);

u_int16_t le2local16(u_int16_t value);

u_int32_t be2local32(u_int32_t value);

u_int32_t le2local32(u_int32_t value);

u_int64_t le2local64(u_int64_t value);

u_int64_t be2local64(u_int64_t value);

#endif
