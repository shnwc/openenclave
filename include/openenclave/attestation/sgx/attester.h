// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/**
 * @file attester.h
 *
 * This file defines the API for getting the SGX attester.
 *
 */

#ifndef _OE_ATTESTATION_SGX_ATTESTER_H
#define _OE_ATTESTATION_SGX_ATTESTER_H

#ifdef _OE_HOST_H
#error "The sgx attester (sgx/attester.h) is only available for the enclave."
#endif

#include <openenclave/attestation/plugin.h>

OE_EXTERNC_BEGIN

/**
 * oe_sgx_get_attesters
 *
 * Helper function that returns the SGX attesters that can then be sent to
 * `oe_register_attester`.
 *
 * @param[out] attesters The list of SGX attesters that are available to the
 * application.
 * @param[out] attesters_length The number of entries in the SGX attesters list
 * @retval OE_OK on success.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval other appropriate error code.
 */
oe_result_t oe_get_attester_plugins(
    oe_attester_t** attesters,
    size_t* attesters_length);

/**
 * oe_initialize_attester_plugins
 *
 * Enumerates all attester plugins and register them
 *
 * @retval OE_OK on success.
 * @retval other appropriate error code.
 */
oe_result_t oe_initialize_attester_plugins(void);

/**
 * oe_sgx_shutdown_attester_plugins
 *
 * Release all resources allocated to attesters, in prep for application
 * shutdown.
 *
 * @retval OE_OK on success.
 * @retval other appropriate error code.
 */
oe_result_t oe_shutdown_attester_plugins(void);

OE_EXTERNC_END

#endif /* _OE_ATTESTATION_SGX_ATTESTER_H */
