// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/**
 * @file attester.h
 *
 * This file defines the programming interface for application enclaves
 * to access the OE SDK attester functionality for evidence generation.
 *
 */

#ifndef _OE_ATTESTATION_ATTESTER_H
#define _OE_ATTESTATION_ATTESTER_H

#ifdef _OE_HOST_H

#error "The header attester.h is only available for the enclave."

#else // _OE_HOST_H

#include <openenclave/bits/evidence.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/**
 * oe_attester_initialize
 *
 * Initializes the attester environment configured for the platform and
 * the calling application.
 * This function is only available in the enclave.
 *
 * This function is idempotent and can be called multiple times without
 * adverse effect.
 *
 * @experimental
 *
 * @retval OE_OK on success.
 * @retval other appropriate error code.
 */
oe_result_t oe_attester_initialize(void);

/**
 * oe_attester_select_format
 *
 * Selects the left-most evidence format from the input list that is supported.
 * This function is only available in the enclave.
 *
 * @experimental
 *
 * @param[in] formats Ordered list of evidence formats from which to
 * select, with descending priority order from left to right.
 * @param[in] formats_length The number of entries in the input evidence
 * format list.
 * @param[out] selected_format Pointer to a caller-supplied buffer to
 * hold the selected evidence format.
 * @retval OE_OK on success.
 * @retval OE_INVALID_PARAMETER At least one of the parameters is invalid.
 * @retval OE_NOT_FOUND if no format in the input list is supported.
 * @retval other appropriate error code.
 */
oe_result_t oe_attester_select_format(
    const oe_uuid_t* formats,
    size_t formats_length,
    oe_uuid_t* selected_format);

/**
 * oe_get_evidence
 *
 * Generates the evidence for the given format UUID.
 * This function is only available in the enclave.
 *
 * @experimental
 *
 * @param[in] format_id The format ID of the evidence to be generated.
 * @param[in] custom_claims The optional custom claims buffer.
 * @param[in] custom_claims_size The number of bytes in the custom claims
 * buffer.
 * @param[in] optional_parameters The optional format-specific input parameters.
 * @param[in] optional_parameters_size The size of optional_parameters in bytes.
 * @param[out] evidence_buffer An output pointer that will be assigned the
 * address of the dynamically allocated evidence buffer.
 * @param[out] evidence_buffer_size A pointer that points to the size of the
 * evidence buffer in bytes.
 * @param[out] endorsements_buffer An output pointer that will be assigned the
 * address of the  dynamically allocated endorsements buffer.
 * @param[out] endorsements_buffer_size A pointer that points to the size of the
 * endorsements buffer in bytes.
 * @retval OE_OK The function succeeded.
 * @retval OE_INVALID_PARAMETER At least one of the parameters is invalid.
 * @retval OE_NOT_FOUND The input evidence format is not supported.
 * @retval other appropriate error code.
 */
oe_result_t oe_get_evidence(
    const oe_uuid_t* format_id,
    const void* custom_claims,
    size_t custom_claims_size,
    const void* optional_parameters,
    size_t optional_parameters_size,
    uint8_t** evidence_buffer,
    size_t* evidence_buffer_size,
    uint8_t** endorsements_buffer,
    size_t* endorsements_buffer_size);

/**
 * oe_free_evidence
 *
 * Frees the attestation evidence.
 * This function is only available in the enclave.
 *
 * @experimental
 *
 * @param[in] evidence_buffer A pointer to the evidence buffer.
 * @retval OE_OK The function succeeded.
 * @retval other appropriate error code.
 */
oe_result_t oe_free_evidence(uint8_t* evidence_buffer);

/**
 * oe_free_endorsements
 *
 * Frees the generated attestation endorsements.
 * This function is only available in the enclave.
 *
 * @experimental
 *
 * @param[in] endorsements_buffer A pointer to the endorsements buffer.
 * @retval OE_OK The function succeeded.
 * @retval other appropriate error code.
 */
oe_result_t oe_free_endorsements(uint8_t* endorsements_buffer);

/**
 * oe_attester_shutdown
 *
 * Shuts down the attester environment configured for the platform and
 * the calling application.
 * This function is only available in the enclave.
 *
 * This function is idempotent and can be called multiple times without
 * adverse effect.
 *
 * @experimental
 *
 * @retval OE_OK on success.
 * @retval other appropriate error code.
 */
oe_result_t oe_attester_shutdown(void);

OE_EXTERNC_END

#endif // _OE_HOST_H

#endif /* _OE_ATTESTATION_ATTESTER_H */
