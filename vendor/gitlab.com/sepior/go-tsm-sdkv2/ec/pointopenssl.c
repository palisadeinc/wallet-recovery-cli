//go:build extlib

#include <unistd.h>
#include <stdatomic.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/engine.h>
#include "pointopenssl.h"

static bool ready = false;
static atomic_flag initialized = ATOMIC_FLAG_INIT;

static EC_GROUP* secp256k1 = NULL;
static EC_GROUP* secp224r1 = NULL;
static EC_GROUP* secp256r1 = NULL;
static EC_GROUP* secp384r1 = NULL;
static EC_GROUP* secp521r1 = NULL;

static inline void initialize() {
    while (!ready) {
        if (!atomic_flag_test_and_set(&initialized)) {
            RAND_poll();
            secp256k1 = EC_GROUP_new_by_curve_name(NID_secp256k1);
            secp224r1 = EC_GROUP_new_by_curve_name(NID_secp224r1);
            secp256r1 = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
            secp384r1 = EC_GROUP_new_by_curve_name(NID_secp384r1);
            secp521r1 = EC_GROUP_new_by_curve_name(NID_secp521r1);
            ready = true;
        }

        usleep(1000);
    }
}

static int32_t export_point(uint8_t* out, uint32_t out_length, EC_GROUP* curve, uint32_t field_element_length, const EC_POINT* p, BN_CTX* ctx) {
    BIGNUM* x = NULL;
    BIGNUM* y = NULL;
    int32_t x_length, y_length;
    int32_t result = ERR_UNSPECIFIED;

    if (out_length < 2 * field_element_length) {
        return ERR_SHORT_BUFFER;
    }

    if (NULL == (x = BN_new())) {
        goto cleanup;
    }

    if (NULL == (y = BN_new())) {
        goto cleanup;
    }

    if (1 == EC_POINT_is_at_infinity(curve, p)) {
        BN_zero(x);
        BN_zero(y);
    } else if (1 != EC_POINT_get_affine_coordinates(curve, p, x, y, ctx)) {
        goto cleanup;
    }

    x_length = BN_num_bytes(x);
    y_length = BN_num_bytes(y);

    if (x_length > field_element_length || y_length > field_element_length) {
        goto cleanup;
    }

    BN_bn2bin(x, out + (0 * field_element_length) + (field_element_length - x_length));
    BN_bn2bin(y, out + (1 * field_element_length) + (field_element_length - y_length));
    result = 2 * field_element_length;
cleanup:

    if (x) {
        BN_free(x);
    }

    if (y) {
        BN_free(y);
    }

    return result;
}

static EC_POINT* import_point(EC_GROUP* curve, uint32_t field_element_length, uint8_t* p, uint32_t p_length, BN_CTX* ctx) {
    BIGNUM* x = NULL;
    BIGNUM* y = NULL;
    EC_POINT* pp = NULL;

    if (p_length < 2 * field_element_length) {
        goto cleanup;
    }

    if (NULL == (x = BN_bin2bn(p + (0 * field_element_length), field_element_length, NULL))) {
        goto cleanup;
    }

    if (NULL == (y = BN_bin2bn(p + (1 * field_element_length), field_element_length, NULL))) {
        goto cleanup;
    }

    if (NULL == (pp = EC_POINT_new(curve))) {
        goto cleanup;
    }

    if (1 == BN_is_zero(x) && 1 == BN_is_zero(y)) {
        if (1 != EC_POINT_set_to_infinity(curve, pp)) {
            EC_POINT_free(pp);
            goto cleanup;
        }
    } else {
        if (1 != EC_POINT_set_affine_coordinates(curve, pp, x, y, ctx)) {
            EC_POINT_free(pp);
            goto cleanup;
        }
    }

cleanup:

    if (x) {
        BN_free(x);
    }

    if (y) {
        BN_free(y);
    }

    return pp;
}

static EC_GROUP* get_curve(uint32_t curve_identifier, uint32_t* field_element_length) {
    switch (curve_identifier) {
        case NID_secp256k1:
            *field_element_length = 32;
            return EC_GROUP_dup(secp256k1);

        case NID_secp224r1:
            *field_element_length = 28;
            return EC_GROUP_dup(secp224r1);

        case NID_X9_62_prime256v1:
            *field_element_length = 32;
            return EC_GROUP_dup(secp256r1);

        case NID_secp384r1:
            *field_element_length = 48;
            return EC_GROUP_dup(secp384r1);

        case NID_secp521r1:
            *field_element_length = 66;
            return EC_GROUP_dup(secp521r1);

        default:
            return EC_GROUP_new_by_curve_name(curve_identifier);
    }
}

inline int32_t point_add(uint8_t* out, uint32_t out_length, uint8_t* p, uint32_t p_length, uint8_t* q, uint32_t q_length, uint32_t curve_identifier) {
    initialize();
    EC_GROUP* curve = NULL;
    BN_CTX* ctx = NULL;
    EC_POINT* pp = NULL;
    EC_POINT* qq = NULL;
    int32_t result = ERR_UNSPECIFIED;
    uint32_t field_element_length;

    if (NULL == (curve = get_curve(curve_identifier, &field_element_length))) {
        goto cleanup;
    }

    if (NULL == (ctx = BN_CTX_new())) {
        goto cleanup;
    }

    if (NULL == (pp = import_point(curve, field_element_length, p, p_length, ctx))) {
        goto cleanup;
    }

    if (NULL == (qq = import_point(curve, field_element_length, q, q_length, ctx))) {
        goto cleanup;
    }

    if (1 != EC_POINT_add(curve, pp, pp, qq, ctx)) {
        goto cleanup;
    }

    result = export_point(out, out_length, curve, field_element_length, pp, ctx);
cleanup:

    if (curve) {
        EC_GROUP_free(curve);
    }

    if (ctx) {
        BN_CTX_free(ctx);
    }

    if (pp) {
        EC_POINT_free(pp);
    }

    if (qq) {
        EC_POINT_free(qq);
    }

    return result;
}

inline int32_t point_multiply(uint8_t* out, uint32_t out_length, uint8_t* p, uint32_t p_length, uint8_t* k, uint32_t k_length, uint32_t curve_identifier, bool base_point, bool constant_time) {
    initialize();
    EC_GROUP* curve = NULL;
    BN_CTX* ctx = NULL;
    BIGNUM* kk = NULL;
    EC_POINT* pp = NULL;
    int32_t result = ERR_UNSPECIFIED;
    uint32_t field_element_length;

    if (NULL == (curve = get_curve(curve_identifier, &field_element_length))) {
        goto cleanup;
    }

    if (NULL == (ctx = BN_CTX_new())) {
        goto cleanup;
    }

    if (NULL == (pp = import_point(curve, field_element_length, p, p_length, ctx))) {
        goto cleanup;
    }

    if (NULL == (kk = BN_bin2bn(k, k_length, NULL))) {
        goto cleanup;
    }

    if (base_point) {
        if (1 != EC_POINT_mul(curve, pp, kk, NULL, NULL, ctx)) {
            goto cleanup;
        }
    } else {
        if (1 != EC_POINT_mul(curve, pp, NULL, pp, kk, ctx)) {
            goto cleanup;
        }
    }

    result = export_point(out, out_length, curve, field_element_length, pp, ctx);
cleanup:

    if (curve) {
        EC_GROUP_free(curve);
    }

    if (ctx) {
        BN_CTX_free(ctx);
    }

    if (kk) {
        BN_free(kk);
    }

    if (pp) {
        EC_POINT_free(pp);
    }

    return result;
}
