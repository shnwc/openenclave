// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_SGX_PLUGIN
#define _OE_INTERNAL_SGX_PLUGIN

#include <openenclave/bits/report.h>

/**
 * The SGX plugin UUID.
 */
#define OE_SGX_PLUGIN_UUID                                                \
    {                                                                     \
        0xa3, 0xa2, 0x1e, 0x87, 0x1b, 0x4d, 0x40, 0x14, 0xb7, 0x0a, 0xa1, \
            0x25, 0xd2, 0xfb, 0xcd, 0x8c                                  \
    }

#define OE_SGX_ECDSA_P256_PLUGIN_UUID OE_SGX_PLUGIN_UUID

#define OE_SGX_LOCAL_ATTESTATION_PLUGIN_UUID                              \
    {                                                                     \
        0x09, 0x26, 0x8c, 0x33, 0x6e, 0x0b, 0x45, 0xe5, 0x8a, 0x27, 0x15, \
            0x64, 0x4d, 0x0e, 0xf8, 0x9a                                  \
    }

#define OE_SGX_EPID_LINKABLE_PLUGIN_UUID                                  \
    {                                                                     \
        0xf2, 0x28, 0xaa, 0x3f, 0xde, 0x4d, 0x49, 0xd3, 0x88, 0x4c, 0xb2, \
            0xaa, 0x87, 0xa5, 0x0d, 0xa6                                  \
    }

#define OE_SGX_EPID_UNLINKABLE_PLUGIN_UUID                                \
    {                                                                     \
        0x5c, 0x35, 0xd2, 0x90, 0xa2, 0xc2, 0x4c, 0x55, 0x9e, 0x13, 0x5a, \
            0xd7, 0x32, 0x74, 0x6c, 0x88                                  \
    }

#define OE_SGX_PLUGIN_CLAIMS_VERSION 1

/**
 *  Serialized header for the custom claims.
 */
typedef struct _oe_sgx_plugin_claims_header
{
    uint64_t version;
    uint64_t num_claims;
} oe_sgx_plugin_claims_header_t;

/**
 * Serialzied entry for custom claims. Each entry will have the name and value
 * sizes and then the contents of the name and value respectively.
 */
typedef struct _oe_sgx_plugin_claims_entry
{
    uint64_t name_size;
    uint64_t value_size;
    uint8_t name[];
    // name_size bytes follow.
    // value_size_bytes follow.
} oe_sgx_plugin_claims_entry_t;

#endif // _OE_INTENRAL_SGX_PLUGIN
