#include <stdio.h>
#include <pcap.h>
#include "endian_converter.h"

/**
 * swap_endian_16 - convert 2-byte integer between endian
 * @value: value need to be converted
 *
 * Return: value correspond to the new endian.
 */

u_int16_t swap_endian_16(u_int16_t value){
	u_int16_t b0, b1;
	u_int16_t res;
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

u_int32_t swap_endian_32(u_int32_t value){
	u_int32_t b0, b1, b2, b3;
	u_int32_t res;

	b0 = (value & 0x000000ff) << 24;
	b1 = (value & 0x0000ff00) << 8;
	b2 = (value & 0x00ff0000) >> 8;
	b3 = (value & 0xff000000) >> 24;

	res = b0 | b1 | b2 | b3;

	return res;
}


u_int64_t swap_endian_64(u_int64_t value){
	u_int64_t b0, b1, b2, b3, b4, b5, b6, b7;
	u_int64_t res;

	b0 = (value & 0x00000000000000ff) << 56;
	b1 = (value & 0x000000000000ff00) << 40;
	b2 = (value & 0x0000000000ff0000) << 24;
	b3 = (value & 0x00000000ff000000) << 8;
	b4 = (value & 0x000000ff00000000) >> 8;
	b5 = (value & 0x0000ff0000000000) >> 24;
	b6 = (value & 0x00ff000000000000) >> 40;
	b7 = (value & 0xff00000000000000) >> 56;

	res = b0 | b1 | b2 | b3 | b4 | b5 | b6 | b7;

	return res;
}


/**
 * is_radiotap_ns - check if the system is little endian or big endian.
 *
 * Return: 1 if it is little endian, otherwise return 0.
 */

u_int8_t is_little_endian(){
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

u_int16_t be2local16(u_int16_t value){
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

u_int16_t le2local16(u_int16_t value){
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

u_int32_t be2local32(u_int32_t value){
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

u_int32_t le2local32(u_int32_t value){
	if (is_little_endian())
		return value;
	else
		return swap_endian_32(value);
}


u_int64_t be2local64(u_int64_t value){
	if (is_little_endian())
		return swap_endian_64(value);
	else
		return value;
}

u_int64_t le2local64(u_int64_t value){
	if (is_little_endian())
		return value;
	else
		return swap_endian_64(value);
}
