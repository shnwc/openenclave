// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/**
 * @file verifier.h
 *
 * This file defines the API for getting the SGX verifier.
 *
 */

#ifndef _OE_ATTESTATION_SGX_VERIFIER_H
#define _OE_ATTESTATION_SGX_VERIFIER_H

#include <openenclave/attestation/plugin.h>

OE_EXTERNC_BEGIN

/**
 * oe_get_verifier_plugins
 *
 * Helper function that returns the built-in verifier plugins that can then be
 * sent to `oe_register_verifier`.
 *
 * @experimental
 * @param[out] verifiers The verifiers that are available to the application.
 * @param[out] verifiers_length The length of the verifiers.
 * @retval OE_OK on success.
 */
oe_result_t oe_get_verifier_plugins(
    oe_verifier_t** verifiers,
    size_t* verifiers_length);

/**
 * oe_initialize_verifier_plugins
 *
 * Enumerates all verifier plugins and register them
 *
 * @retval OE_OK on success.
 * @retval other appropriate error code.
 */
oe_result_t oe_initialize_verifier_plugins(void);

/**
 * oe_sgx_shutdown_verifier_plugins
 *
 * Release all resources allocated to verifiers, in prep for application
 * shutdown.
 *
 * @retval OE_OK on success.
 * @retval other appropriate error code.
 */
oe_result_t oe_shutdown_verifier_plugins(void);

OE_EXTERNC_END

#endif /* _OE_ATTESTATION_SGX_ATTESTER_H */
