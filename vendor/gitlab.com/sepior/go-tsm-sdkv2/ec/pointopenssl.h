//go:build extlib

#include <stdbool.h>
#include <stdint.h>

#ifndef POINTOPENSSL_H
#define POINTOPENSSL_H

#define ERR_UNSPECIFIED -1
#define ERR_SHORT_BUFFER -2
#define ERR_WRONG_ALG -3

int32_t point_add(uint8_t* out, uint32_t out_length, uint8_t* p, uint32_t p_length, uint8_t* q, uint32_t q_length, uint32_t curve_identifier);
int32_t point_multiply(uint8_t* out, uint32_t out_length, uint8_t* p, uint32_t p_length, uint8_t* k, uint32_t k_length, uint32_t curve_identifier, bool base_point, bool constant_time);

#endif
