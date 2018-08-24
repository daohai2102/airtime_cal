#ifndef _SWAP_ENDIAN_H
#define _SWAP_ENDIAN_H

#include <stdint.h>

uint16_t swap_endian_16(uint16_t value);

uint32_t swap_endian_32(uint32_t value);

uint8_t is_little_endian();

uint16_t be2local16(uint16_t value);

uint16_t le2local16(uint16_t value);

uint32_t be2local32(uint32_t value);

uint32_t le2local32(uint32_t value);

#endif
