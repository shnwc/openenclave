// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/plugin.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/safemath.h>
#include <openenclave/internal/sgx/plugin.h>

#include "../attest_plugin.h"
#include "../common.h"
#include "endorsements.h"
#include "quote.h"
#include "report.h"

#if !defined(OE_BUILD_ENCLAVE)
#include "../../host/sgx/sgxquoteprovider.h"
#endif

#ifdef OE_BUILD_ENCLAVE
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/thread.h>
#include "../../enclave/core/sgx/report.h"
#include "../enclave/sgx/report.h"
#else
#include "../../host/hostthread.h"
#include "../../host/sgx/quote.h"
typedef oe_mutex oe_mutex_t;
#define OE_MUTEX_INITIALIZER OE_H_MUTEX_INITIALIZER
#endif

static const oe_uuid_t _uuid_sgx_local = {OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION};
static const oe_uuid_t _uuid_sgx_ecdsa = {OE_FORMAT_UUID_SGX_ECDSA};
static const oe_uuid_t _uuid_legacy_report_remote = {
    OE_FORMAT_UUID_LEGACY_REPORT_REMOTE};
static const oe_uuid_t _uuid_raw_sgx_quote_ecdsa = {
    OE_FORMAT_UUID_RAW_SGX_QUOTE_ECDSA};

static oe_result_t _on_register(
    oe_attestation_role_t* context,
    const void* configuration_data,
    size_t configuration_data_size)
{
    OE_UNUSED(context);
    OE_UNUSED(configuration_data);
    OE_UNUSED(configuration_data_size);

#if defined(OE_BUILD_ENCLAVE)
    return OE_OK;
#else
    return oe_initialize_quote_provider();
#endif
}

static oe_result_t _on_unregister(oe_attestation_role_t* context)
{
    OE_UNUSED(context);
    return OE_OK;
}

static void _free_claim(oe_claim_t* claim)
{
    oe_free(claim->name);
    oe_free(claim->value);
}

static oe_result_t _free_claims(
    oe_verifier_t* context,
    oe_claim_t* claims,
    size_t claims_length)
{
    OE_UNUSED(context);
    if (!claims)
        return OE_OK;

    for (size_t i = 0; i < claims_length; i++)
        _free_claim(&claims[i]);
    oe_free(claims);
    return OE_OK;
}

static oe_result_t _get_input_time(
    const oe_policy_t* policies,
    size_t policies_size,
    oe_datetime_t** time)
{
    if (!policies)
    {
        *time = NULL;
        return OE_OK;
    }

    for (size_t i = 0; i < policies_size; i++)
    {
        if (policies[i].type == OE_POLICY_ENDORSEMENTS_TIME)
        {
            if (policies[i].policy_size != sizeof(**time))
                return OE_INVALID_PARAMETER;

            *time = (oe_datetime_t*)policies[i].policy;
            return OE_OK;
        }
    }

    // Time not found, which is fine since it's an optional parameter.
    *time = NULL;
    return OE_OK;
}

static oe_result_t _verify_local_report(
    const uint8_t* report_body,
    size_t report_body_size)
{
    // Do a normal report verification on the enclave side.
    // Local report verification is unsupported for host side.
#ifdef OE_BUILD_ENCLAVE
    return oe_verify_raw_sgx_report(report_body, report_body_size);
#else
    OE_UNUSED(report_body);
    OE_UNUSED(report_body_size);
    return OE_UNSUPPORTED;
#endif
}

// If evidence contains custom claims, verify the custom claims' hash;
// otherwise return SGX report data as a claim field.
static oe_result_t _process_sgx_report_data(
    const sgx_evidence_format_type_t format_type,
    const uint8_t* report_body, // Raw SGX quote or report
    const uint8_t* custom_claims_buffer,
    size_t custom_claims_buffer_size,
    sgx_report_data_t* report_data_out)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!report_body)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Evidence generated by oe_get_evidence() has its custom claims buffer
    // hashed for the SGX report data.
    if (format_type == SGX_FORMAT_TYPE_LOCAL ||
        format_type == SGX_FORMAT_TYPE_REMOTE)
    {
        // Verify custom claims
        OE_SHA256 hash;
        uint8_t* report_data;

        OE_UNUSED(report_data_out);

        OE_CHECK(oe_sgx_hash_custom_claims_buffer(
            custom_claims_buffer, custom_claims_buffer_size, &hash));

        if (format_type == SGX_FORMAT_TYPE_REMOTE)
            report_data =
                (uint8_t*)&((sgx_quote_t*)report_body)->report_body.report_data;
        else
            report_data =
                (uint8_t*)&((sgx_report_t*)report_body)->body.report_data;

        result = !memcmp(report_data, &hash, OE_SHA256_SIZE)
                     ? OE_OK
                     : OE_QUOTE_HASH_MISMATCH;
    }
    else // SGX_FORMAT_TYPE_LEGACY_REPORT or SGX_FORMAT_TYPE_RAW_QUOTE
    {
        // These types of evidence does not contain custom claims buffer.
        // SGX report data is returned.

        OE_UNUSED(custom_claims_buffer);
        OE_UNUSED(custom_claims_buffer_size);

        if (!report_data_out)
            OE_RAISE(OE_INVALID_PARAMETER);

        *report_data_out = ((sgx_quote_t*)report_body)->report_body.report_data;

        result = OE_OK;
    }
done:
    return result;
}

static oe_result_t _add_claim(
    oe_claim_t* claim,
    const void* name,
    size_t name_size, // Must cover the '\0' at end of string
    const void* value,
    size_t value_size)
{
    if (*((uint8_t*)name + name_size - 1) != '\0')
        return OE_CONSTRAINT_FAILED;

    claim->name = (char*)oe_malloc(name_size);
    if (claim->name == NULL)
        return OE_OUT_OF_MEMORY;
    memcpy(claim->name, name, name_size);

    claim->value = (uint8_t*)oe_malloc(value_size);
    if (claim->value == NULL)
    {
        oe_free(claim->name);
        claim->name = NULL;
        return OE_OUT_OF_MEMORY;
    }
    memcpy(claim->value, value, value_size);
    claim->value_size = value_size;

    return OE_OK;
}

static oe_result_t _fill_with_known_claims(
    const sgx_evidence_format_type_t format_type,
    const oe_uuid_t* format_id,
    const uint8_t* report_body,
    size_t report_body_size,
    const oe_sgx_endorsements_t* sgx_endorsements,
    oe_claim_t* claims,
    size_t claims_length,
    size_t* claims_added)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_report_t parsed_report = {0};
    oe_identity_t* id = &parsed_report.identity;
    size_t claims_index = 0;
    oe_datetime_t valid_from = {0};
    oe_datetime_t valid_until = {0};

    if (claims_length < OE_REQUIRED_CLAIMS_COUNT)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (format_type == SGX_FORMAT_TYPE_LOCAL)
        OE_CHECK(oe_parse_sgx_report_body(
            &((sgx_report_t*)report_body)->body, false, &parsed_report));
    else
        OE_CHECK(oe_parse_sgx_report_body(
            &((sgx_quote_t*)report_body)->report_body, true, &parsed_report));

    // Optional claims are needed for SGX quotes for remote attestation
    if (format_type != SGX_FORMAT_TYPE_LOCAL &&
        claims_length < OE_REQUIRED_CLAIMS_COUNT + OE_OPTIONAL_CLAIMS_COUNT +
                            OE_SGX_CLAIMS_COUNT)
        OE_RAISE(OE_INVALID_PARAMETER);

    // ID version.
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_ID_VERSION,
        sizeof(OE_CLAIM_ID_VERSION),
        &id->id_version,
        sizeof(id->id_version)));

    // Security version.
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_SECURITY_VERSION,
        sizeof(OE_CLAIM_SECURITY_VERSION),
        &id->security_version,
        sizeof(id->security_version)));

    // Attributes.
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_ATTRIBUTES,
        sizeof(OE_CLAIM_ATTRIBUTES),
        &id->attributes,
        sizeof(id->attributes)));

    // Unique ID
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_UNIQUE_ID,
        sizeof(OE_CLAIM_UNIQUE_ID),
        &id->unique_id,
        sizeof(id->unique_id)));

    // Signer ID
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_SIGNER_ID,
        sizeof(OE_CLAIM_SIGNER_ID),
        &id->signer_id,
        sizeof(id->signer_id)));

    // Product ID
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_PRODUCT_ID,
        sizeof(OE_CLAIM_PRODUCT_ID),
        &id->product_id,
        sizeof(id->product_id)));

    // Plugin UUID
    OE_CHECK(_add_claim(
        &claims[claims_index++],
        OE_CLAIM_FORMAT_UUID,
        sizeof(OE_CLAIM_FORMAT_UUID),
        format_id,
        sizeof(*format_id)));

    if (format_type != SGX_FORMAT_TYPE_LOCAL)
    {
        // Get quote validity periods to get validity from and until claims.
        OE_CHECK(oe_get_sgx_quote_validity(
            report_body,
            report_body_size,
            sgx_endorsements,
            &valid_from,
            &valid_until));

        // Validity from.
        OE_CHECK(_add_claim(
            &claims[claims_index++],
            OE_CLAIM_VALIDITY_FROM,
            sizeof(OE_CLAIM_VALIDITY_FROM),
            &valid_from,
            sizeof(valid_from)));

        // Validity to.
        OE_CHECK(_add_claim(
            &claims[claims_index++],
            OE_CLAIM_VALIDITY_UNTIL,
            sizeof(OE_CLAIM_VALIDITY_UNTIL),
            &valid_until,
            sizeof(valid_until)));

        // TCB info
        OE_CHECK(_add_claim(
            &claims[claims_index++],
            OE_CLAIM_SGX_TCB_INFO,
            sizeof(OE_CLAIM_SGX_TCB_INFO),
            sgx_endorsements->items[OE_SGX_ENDORSEMENT_FIELD_TCB_INFO].data,
            sgx_endorsements->items[OE_SGX_ENDORSEMENT_FIELD_TCB_INFO].size));

        // TCB issuer chain
        OE_CHECK(_add_claim(
            &claims[claims_index++],
            OE_CLAIM_SGX_TCB_ISSUER_CHAIN,
            sizeof(OE_CLAIM_SGX_TCB_ISSUER_CHAIN),
            sgx_endorsements->items[OE_SGX_ENDORSEMENT_FIELD_TCB_ISSUER_CHAIN]
                .data,
            sgx_endorsements->items[OE_SGX_ENDORSEMENT_FIELD_TCB_ISSUER_CHAIN]
                .size));

        // PCK CRL
        OE_CHECK(_add_claim(
            &claims[claims_index++],
            OE_CLAIM_SGX_PCK_CRL,
            sizeof(OE_CLAIM_SGX_PCK_CRL),
            sgx_endorsements->items[OE_SGX_ENDORSEMENT_FIELD_CRL_PCK_CERT].data,
            sgx_endorsements->items[OE_SGX_ENDORSEMENT_FIELD_CRL_PCK_CERT]
                .size));

        // Root CA CRL
        OE_CHECK(_add_claim(
            &claims[claims_index++],
            OE_CLAIM_SGX_ROOT_CA_CRL,
            sizeof(OE_CLAIM_SGX_ROOT_CA_CRL),
            sgx_endorsements->items[OE_SGX_ENDORSEMENT_FIELD_CRL_PCK_PROC_CA]
                .data,
            sgx_endorsements->items[OE_SGX_ENDORSEMENT_FIELD_CRL_PCK_PROC_CA]
                .size));

        // CRL Issuer Chain
        OE_CHECK(_add_claim(
            &claims[claims_index++],
            OE_CLAIM_SGX_CRL_ISSUER_CHAIN,
            sizeof(OE_CLAIM_SGX_CRL_ISSUER_CHAIN),
            sgx_endorsements
                ->items[OE_SGX_ENDORSEMENT_FIELD_CRL_ISSUER_CHAIN_PCK_CERT]
                .data,
            sgx_endorsements
                ->items[OE_SGX_ENDORSEMENT_FIELD_CRL_ISSUER_CHAIN_PCK_CERT]
                .size));

        // QE ID info
        OE_CHECK(_add_claim(
            &claims[claims_index++],
            OE_CLAIM_SGX_QE_ID_INFO,
            sizeof(OE_CLAIM_SGX_QE_ID_INFO),
            sgx_endorsements->items[OE_SGX_ENDORSEMENT_FIELD_QE_ID_INFO].data,
            sgx_endorsements->items[OE_SGX_ENDORSEMENT_FIELD_QE_ID_INFO].size));

        // QE ID issuer chain
        OE_CHECK(_add_claim(
            &claims[claims_index++],
            OE_CLAIM_SGX_QE_ID_ISSUER_CHAIN,
            sizeof(OE_CLAIM_SGX_QE_ID_ISSUER_CHAIN),
            sgx_endorsements->items[OE_SGX_ENDORSEMENT_FIELD_QE_ID_ISSUER_CHAIN]
                .data,
            sgx_endorsements->items[OE_SGX_ENDORSEMENT_FIELD_QE_ID_ISSUER_CHAIN]
                .size));
    }

    *claims_added = claims_index;
    result = OE_OK;

done:
    if (result != OE_OK)
    {
        for (size_t i = 0; i < claims_index; i++)
            _free_claim(&claims[i]);
    }
    return result;
}

oe_result_t oe_sgx_hash_custom_claims_buffer(
    const void* custom_claims_buffer,
    size_t custom_claims_buffer_size,
    OE_SHA256* hash_out)
{
    oe_result_t result = OE_UNEXPECTED;
    // Default hash for empty string, as described in the literature.
    static const uint8_t sha256_for_empty_string[] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4,
        0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b,
        0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};

    // Produce a hash of the custom_claims_buffer.
    // If there is no data, set to default value
    if (!custom_claims_buffer || !custom_claims_buffer_size)
        memcpy(hash_out, sha256_for_empty_string, sizeof(*hash_out));
    else
        // Produce a hash of the custom_claims_buffer.
        OE_CHECK(oe_sha256(
            custom_claims_buffer, custom_claims_buffer_size, hash_out));

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_sgx_extract_claims(
    const sgx_evidence_format_type_t format_type,
    const oe_uuid_t* format_id,
    const uint8_t* report_body,
    size_t report_body_size,
    const uint8_t* custom_claims_buffer,
    size_t custom_claims_buffer_size,
    const oe_sgx_endorsements_t* sgx_endorsements,
    oe_claim_t** claims_out,
    size_t* claims_length_out)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_claim_t* claims = NULL;
    uint64_t claims_length = 0;
    uint64_t claims_size = 0;
    size_t claims_added = 0;
    size_t additional_claim = 0;
    sgx_report_data_t report_data;

    // Note: some callers can have custom_claims_buffer pointing to a non-NULL
    // buffer containing a zero-sized array.
    if (!format_id || !report_body || !report_body_size ||
        (!custom_claims_buffer && custom_claims_buffer_size))
        OE_RAISE(OE_INVALID_PARAMETER);

    // verify the integrity of the custom_claims_buffer with hash stored in
    // report_body, or retrieve the SGX report data
    OE_CHECK(_process_sgx_report_data(
        format_type,
        report_body,
        custom_claims_buffer,
        custom_claims_buffer_size,
        &report_data));

    // If provided, custom_claims_buffer can only be the
    // OE_CLAIM_CUSTOM_CLAIMS_BUFFER or OE_CLAIM_SGX_REPORT_DATA types.
    if ((format_type == SGX_FORMAT_TYPE_LOCAL ||
         format_type == SGX_FORMAT_TYPE_REMOTE) &&
        (!custom_claims_buffer || !custom_claims_buffer_size))
        additional_claim = 0;
    else
        additional_claim = 1;

    // Get the number of claims we need and allocate the claims.
    OE_CHECK(oe_safe_add_u64(
        OE_REQUIRED_CLAIMS_COUNT, additional_claim, &claims_length));

    if (format_type != SGX_FORMAT_TYPE_LOCAL)
    {
        OE_CHECK(oe_safe_add_u64(
            claims_length,
            OE_OPTIONAL_CLAIMS_COUNT + OE_SGX_CLAIMS_COUNT,
            &claims_length));
    }

    OE_CHECK(oe_safe_mul_u64(claims_length, sizeof(oe_claim_t), &claims_size));

    claims = (oe_claim_t*)oe_malloc(claims_size);
    if (claims == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    // Fill the list with the known claims.
    OE_CHECK(_fill_with_known_claims(
        format_type,
        format_id,
        report_body,
        report_body_size,
        sgx_endorsements,
        claims,
        claims_length,
        &claims_added));

    // Fill with the additional claim
    if (additional_claim)
    {
        if (format_type == SGX_FORMAT_TYPE_LOCAL ||
            format_type == SGX_FORMAT_TYPE_REMOTE)
        {
            // Add custom claims buffer
            char* name = OE_CLAIM_CUSTOM_CLAIMS_BUFFER;
            OE_CHECK(_add_claim(
                claims + claims_added,
                name,
                oe_strlen(name) + 1,
                custom_claims_buffer,
                custom_claims_buffer_size));
        }
        else // SGX_FORMAT_TYPE_LEGACY_REPORT and _QUOTE
        {
            // Add SGX report data claim
            char* name = OE_CLAIM_SGX_REPORT_DATA;
            OE_CHECK(_add_claim(
                claims + claims_added,
                name,
                oe_strlen(name) + 1,
                &report_data,
                sizeof(report_data)));
        }
    }

    *claims_out = claims;
    *claims_length_out = claims_length;
    claims = NULL;
    result = OE_OK;

done:
    if (claims)
        _free_claims(NULL, claims, claims_length);
    return result;
}

static oe_result_t _verify_evidence(
    oe_verifier_t* context,
    const uint8_t* evidence_buffer,
    size_t evidence_buffer_size,
    const uint8_t* endorsements_buffer,
    size_t endorsements_buffer_size,
    const oe_policy_t* policies,
    size_t policies_size,
    oe_claim_t** claims,
    size_t* claims_length)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_datetime_t* time = NULL;
    uint8_t* local_endorsements_buffer = NULL;
    size_t local_endorsements_buffer_size = 0;
    oe_sgx_endorsements_t sgx_endorsements;
    sgx_evidence_format_type_t format_type = SGX_FORMAT_TYPE_UNKNOWN;
    const uint8_t* report_body = NULL;
    size_t report_body_size = 0;
    const uint8_t* custom_claims_buffer = NULL;
    size_t custom_claims_buffer_size = 0;
    oe_uuid_t* format_id = NULL;

    if (!context || !evidence_buffer || !evidence_buffer_size || !claims ||
        !claims_length)
        OE_RAISE(OE_INVALID_PARAMETER);

    format_id = &context->base.format_id;

    // Check the datetime policy if it exists.
    OE_CHECK(_get_input_time(policies, policies_size, &time));

    if (!memcmp(format_id, &_uuid_sgx_local, sizeof(oe_uuid_t)))
    {
        // evidence_buffer has an SGX report for local attestation
        // followed by an optional custom claims buffer.
        // Note: sgx_report_t has no field that can be checked quickly
        // to verify it being an SGX report.

        if (evidence_buffer_size < sizeof(sgx_report_t))
            OE_RAISE(OE_INVALID_PARAMETER);

        format_type = SGX_FORMAT_TYPE_LOCAL;
    }
    else if (!memcmp(format_id, &_uuid_sgx_ecdsa, sizeof(oe_uuid_t)))
    {
        // evidence_buffer has an SGX ECDSA-p256 quote
        // followed by an optional custom claims buffer.
        sgx_quote_t* quote = (sgx_quote_t*)evidence_buffer;

        if (evidence_buffer_size < sizeof(*quote) + quote->signature_len ||
            quote->version != SGX_QE3_QUOTE_VERSION ||
            quote->sign_type != SGX_QL_ALG_ECDSA_P256)
            OE_RAISE(OE_INVALID_PARAMETER);

        format_type = SGX_FORMAT_TYPE_REMOTE;
    }
    else if (!memcmp(format_id, &_uuid_legacy_report_remote, sizeof(oe_uuid_t)))
    {
        // evidence_buffer has an oe_report_header_t header
        // followed by an SGX report or ECDSA-p256 quote.
        oe_report_header_t* report = (oe_report_header_t*)evidence_buffer;

        if (evidence_buffer_size < sizeof(*report) ||
            report->version != OE_REPORT_HEADER_VERSION ||
            report->report_type != OE_REPORT_TYPE_SGX_REMOTE)
            OE_RAISE(OE_INVALID_PARAMETER);

        format_type = SGX_FORMAT_TYPE_LEGACY_REPORT;
    }
    else if (!memcmp(format_id, &_uuid_raw_sgx_quote_ecdsa, sizeof(oe_uuid_t)))
    {
        // evidence_buffer has no header.
        // It holds an SGX ECDSA_p256 quote generated by the Intel SGX DCAP
        // or quote-ex library.
        sgx_quote_t* quote = (sgx_quote_t*)evidence_buffer;

        if (evidence_buffer_size < sizeof(*quote) + quote->signature_len ||
            quote->version != SGX_QE3_QUOTE_VERSION ||
            quote->sign_type != SGX_QL_ALG_ECDSA_P256)
            OE_RAISE(OE_INVALID_PARAMETER);

        format_type = SGX_FORMAT_TYPE_RAW_QUOTE;
    }
    else
        OE_RAISE(OE_INVALID_PARAMETER);

    // Verify the report. Send the report size to just the oe report,
    // not including the custom claims section.
    if (format_type == SGX_FORMAT_TYPE_LOCAL)
    {
        report_body = evidence_buffer;
        report_body_size = sizeof(sgx_report_t);
        custom_claims_buffer = report_body + report_body_size;
        custom_claims_buffer_size = evidence_buffer_size - report_body_size;

        OE_CHECK(_verify_local_report(report_body, report_body_size));
    }
    else
    {
        if (format_type == SGX_FORMAT_TYPE_REMOTE)
        {
            sgx_quote_t* quote = (sgx_quote_t*)evidence_buffer;

            report_body = evidence_buffer;
            report_body_size = sizeof(*quote) + quote->signature_len;
            custom_claims_buffer = report_body + report_body_size;
            custom_claims_buffer_size = evidence_buffer_size - report_body_size;
        }
        else if (format_type == SGX_FORMAT_TYPE_LEGACY_REPORT)
        {
            oe_report_header_t* report = (oe_report_header_t*)evidence_buffer;
            report_body = report->report;
            report_body_size = report->report_size;
            custom_claims_buffer = NULL;
            custom_claims_buffer_size = 0;
        }
        else // SGX_FORMAT_TYPE_RAW_QUOTE
        {
            report_body = evidence_buffer;
            report_body_size = evidence_buffer_size;
            custom_claims_buffer = NULL;
            custom_claims_buffer_size = 0;
        }

        // Get the endorsements if none were provided.
        if (endorsements_buffer == NULL)
        {
            OE_CHECK(oe_get_sgx_endorsements(
                report_body,
                report_body_size,
                &local_endorsements_buffer,
                &local_endorsements_buffer_size));
            endorsements_buffer = local_endorsements_buffer;
            endorsements_buffer_size = local_endorsements_buffer_size;
        }

        // Parse into SGX endorsements.
        OE_CHECK(oe_parse_sgx_endorsements(
            (oe_endorsements_t*)endorsements_buffer,
            endorsements_buffer_size,
            &sgx_endorsements));

        // Verify the quote now.
        OE_CHECK(oe_verify_quote_with_sgx_endorsements(
            report_body, report_body_size, &sgx_endorsements, time));
    }

    // Last step is to return the required and custom claims.
    OE_CHECK(oe_sgx_extract_claims(
        format_type,
        format_id,
        report_body,
        report_body_size,
        custom_claims_buffer,
        custom_claims_buffer_size,
        &sgx_endorsements,
        claims,
        claims_length));

    // Avoid running the loop unless traces are actually generated
    if (oe_get_current_logging_level() >= OE_LOG_LEVEL_INFO)
    {
        OE_TRACE_INFO("extracted %lu claims", *claims_length);
        for (size_t i = 0; i < *claims_length; i++)
        {
            OE_TRACE_INFO(
                "claim %s[%lu]: ", (*claims)[i].name, (*claims)[i].value_size);
            oe_hex_dump((*claims)[i].value, (*claims)[i].value_size);
        }
    }

    result = OE_OK;

done:
    if (local_endorsements_buffer)
        oe_free_sgx_endorsements(local_endorsements_buffer);

    return result;
}

// Gets the optional format settings for the given verifier plugin context.
// For SGX local attestation, this would be the sgx_target_info_t struct.
static oe_result_t _get_format_settings(
    oe_verifier_t* context,
    uint8_t** settings,
    size_t* settings_size)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_report_header_t* report = NULL;

    if (!context || !settings || !settings_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!memcmp(&context->base.format_id, &_uuid_sgx_local, sizeof(oe_uuid_t)))
    {
#ifdef OE_BUILD_ENCLAVE
        // Enclave-side, SGX local attestation is supported
        uint8_t* tmp_target = NULL;
        size_t tmp_target_size = 0;

        report = (oe_report_header_t*)oe_malloc(
            sizeof(oe_report_header_t) + sizeof(sgx_report_t));
        if (!report)
            OE_RAISE(OE_OUT_OF_MEMORY);

        OE_CHECK(sgx_create_report(
            NULL, 0, NULL, 0, (sgx_report_t*)&report->report));

        report->version = OE_REPORT_HEADER_VERSION;
        report->report_type = OE_REPORT_TYPE_SGX_LOCAL;
        report->report_size = sizeof(sgx_report_t);

        OE_CHECK(oe_get_target_info_v2(
            (const uint8_t*)report,
            sizeof(oe_report_header_t) + sizeof(sgx_report_t),
            (void**)&tmp_target,
            &tmp_target_size));

        *settings = tmp_target;
        *settings_size = tmp_target_size;
        tmp_target = NULL;
        result = OE_OK;
#else
        // Host-side, SGX local attestation is not supported
        OE_RAISE(OE_UNSUPPORTED);
#endif
    }
    else if (!memcmp(
                 &context->base.format_id, &_uuid_sgx_ecdsa, sizeof(oe_uuid_t)))
    {
        *settings = NULL;
        *settings_size = 0;
        result = OE_OK;
    }
    else
    {
        OE_RAISE(OE_UNSUPPORTED);
    }

done:
    if (report)
        oe_free(report);
    return result;
}

static oe_result_t _verify_report(
    oe_verifier_t* context,
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!context || !report || report_size == 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Enclave-side, verifies ECDSA and local report
    // Host-side, verifies only ECDSA report
    if (
#ifdef OE_BUILD_ENCLAVE
        !memcmp(
            &context->base.format_id, &_uuid_sgx_local, sizeof(oe_uuid_t)) ||
#endif
        !memcmp(&context->base.format_id, &_uuid_sgx_ecdsa, sizeof(oe_uuid_t)))
    {
#ifdef OE_BUILD_ENCLAVE
        OE_CHECK(oe_verify_report_internal(report, report_size, parsed_report));
#else
        OE_CHECK(oe_verify_report_internal(
            NULL, report, report_size, parsed_report));
#endif
        result = OE_OK;
    }
    else
        OE_RAISE(OE_UNSUPPORTED);

done:
    return result;
}

static oe_result_t _get_verifier_plugins(
    oe_verifier_t** verifiers,
    size_t* verifiers_length)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t uuid_count = 0;
    const oe_uuid_t* uuids[4];

    if (!verifiers || !verifiers_length)
        OE_RAISE(OE_INVALID_PARAMETER);

    uuids[0] = &_uuid_sgx_ecdsa;
    uuids[1] = &_uuid_legacy_report_remote;
    uuids[2] = &_uuid_raw_sgx_quote_ecdsa;

#ifdef OE_BUILD_ENCLAVE
    uuids[3] = &_uuid_sgx_local;
    uuid_count =
        4; // In enclave, local attestation and 3 ECDSA formats are supported.
#else
    // On the host side, only 3 ECDSA formats are supported.
    // Note: SGX local attestation can only be performed between enclaves.
    uuid_count = 3;
#endif

    *verifiers = (oe_verifier_t*)oe_malloc(sizeof(oe_verifier_t) * uuid_count);
    if (*verifiers == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    for (size_t i = 0; i < uuid_count; i++)
    {
        oe_verifier_t* plugin = *verifiers + i;
        plugin->base.format_id = *uuids[i];
        plugin->base.on_register = &_on_register;
        plugin->base.on_unregister = &_on_unregister;
        plugin->get_format_settings = &_get_format_settings;
        plugin->verify_evidence = &_verify_evidence;
        plugin->verify_report = &_verify_report;
        plugin->free_claims = &_free_claims;
    }
    *verifiers_length = uuid_count;
    result = OE_OK;

done:
    return result;
}

static oe_verifier_t* verifiers = NULL;
static size_t verifiers_length = 0;
static oe_mutex_t init_mutex = OE_MUTEX_INITIALIZER;

oe_result_t oe_verifier_initialize(void)
{
    oe_result_t result = OE_UNEXPECTED;

    if (oe_mutex_lock(&init_mutex))
        OE_RAISE(OE_UNEXPECTED);

    // Do nothing if verifier plugins are already initialized
    if (verifiers)
    {
        OE_TRACE_INFO(
            "verifiers is not NULL, verifiers_length=%d", verifiers_length);
        result = OE_OK;
        goto done;
    }

    OE_CHECK(_get_verifier_plugins(&verifiers, &verifiers_length));

    OE_TRACE_INFO("got verifiers_length=%d plugins", verifiers_length);

    for (size_t i = 0; i < verifiers_length; i++)
    {
        result = oe_register_verifier_plugin(verifiers + i, NULL, 0);
        OE_CHECK(result);
    }
    result = OE_OK;

done:
    oe_mutex_unlock(&init_mutex);
    return result;
}

// Registration of plugins does not allocate any resources to them.
oe_result_t oe_verifier_shutdown(void)
{
    oe_result_t result = OE_UNEXPECTED;

    if (oe_mutex_lock(&init_mutex))
        OE_RAISE(OE_UNEXPECTED);

    // Either verifier plugins have not been initialized,
    // or there is no supported plugin
    if (!verifiers)
    {
        OE_TRACE_INFO("verifiers is NULL");
        result = OE_OK;
        goto done;
    }

    OE_TRACE_INFO("free verifiers_length=%d plugins", verifiers_length);

    for (size_t i = 0; i < verifiers_length; i++)
    {
        result = oe_unregister_verifier_plugin(verifiers + i);
        if (result != OE_OK)
            OE_TRACE_ERROR(
                "oe_unregister_verifier_plugin() #%lu failed with %s",
                i,
                oe_result_str(result));
    }

    oe_free(verifiers);
    verifiers = NULL;
    verifiers_length = 0;
    result = OE_OK;

done:
    oe_mutex_unlock(&init_mutex);
    return result;
}
