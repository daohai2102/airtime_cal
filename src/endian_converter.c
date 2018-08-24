#include <stdio.h>
#include <stdint.h>
#include "endian_converter.h"

/**
 * swap_endian_16 - convert 2-byte integer between endian
 * @value: value need to be converted
 *
 * Return: value correspond to the new endian.
 */

uint16_t swap_endian_16(uint16_t value){
	uint16_t b0, b1;
	uint16_t res;
	b0 = (value & 0x00ff) << 8;
	b1 = (value & 0xff00) >> 8;

	res = b0 | b1;
	return res;
}


/**
 * swap_endian_32 - convert 4-byte integer between endian
 * @value: value need to be converted.
 *
 * Return: value correspond to the new endian.
 */

uint32_t swap_endian_32(uint32_t value){
	uint32_t b0, b1, b2, b3;
	uint32_t res;

	b0 = (value & 0x000000ff) << 24;
	b1 = (value & 0x0000ff00) << 8;
	b2 = (value & 0x00ff0000) >> 8;
	b3 = (value & 0xff000000) >> 24;

	res = b0 | b1 | b2 | b3;

	return res;
}


/**
 * is_radiotap_ns - check if the system is little endian or big endian.
 *
 * Return: 1 if it is little endian, otherwise return 0.
 */

uint8_t is_little_endian(){
	int a = 1;
	if (*(char*)&a)
		return 1;
	else
		return 0;
}


/**
 * be2local16 - convert 2-byte integer from big endian to the system's endian.
 * @value: the value need to be converted.
 *
 * Return: value after converting.
 */

uint16_t be2local16(uint16_t value){
	if (is_little_endian())
		return swap_endian_16(value);
	else
		return value;
}


/**
 * le2local16 - convert 2-byte integer from little endian to the system's endian/
 * @value: value need to be converted.
 *
 * Return: value after converting.
 */

uint16_t le2local16(uint16_t value){
	if (is_little_endian())
		return value;
	else
		return swap_endian_16(value);
}


/**
 * be2local32 - convert 4-byte integer from big endian to the system's endian/
 * @value: value need to be converted.
 *
 * Return: value after converting.
 */

uint32_t be2local32(uint32_t value){
	if (is_little_endian())
		return swap_endian_32(value);
	else
		return value;
}	

/**
 * le2local32 - convert 4-byte integer from little endian to the system's endian/
 * @value: value need to be converted.
 *
 * Return: value after converting.
 */

uint32_t le2local32(uint32_t value){
	if (is_little_endian())
		return value;
	else
		return swap_endian_32(value);
}
