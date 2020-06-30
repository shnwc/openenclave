// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/defs.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/safemath.h>
#include <openenclave/internal/utils.h>
#include <stdio.h>
#include <string.h>

#include "../common/attest_plugin.h"
#include "../common/common.h"

#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/internal/plugin.h>

// Variables storing the attester list.
static oe_plugin_list_node_t* attesters = NULL;

oe_result_t oe_register_attester_plugin(
    oe_attester_t* plugin,
    const void* configuration_data,
    size_t configuration_data_size)
{
    return oe_attest_register_plugin(
        &attesters,
        (oe_attestation_role_t*)plugin,
        configuration_data,
        configuration_data_size);
}

oe_result_t oe_unregister_attester_plugin(oe_attester_t* plugin)
{
    return oe_attest_unregister_plugin(
        &attesters, (oe_attestation_role_t*)plugin);
}

oe_result_t oe_fill_attestation_header(
    const oe_uuid_t* format_id,
    const uint8_t* data,
    size_t data_size,
    oe_attestation_header_t* header)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!format_id || !data || !data_size || !header)
        OE_RAISE(OE_INVALID_PARAMETER);

    // The header must prefix the data
    if ((uint8_t*)header + sizeof(*header) != data)
        OE_RAISE(OE_CONSTRAINT_FAILED);

    header->version = OE_ATTESTATION_HEADER_VERSION;
    header->format_id = *format_id;
    header->data_size = data_size;

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_wrap_with_attestation_header(
    const oe_uuid_t* format_id,
    const uint8_t* data,
    size_t data_size,
    uint8_t** total_data,
    size_t* total_data_size)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_attestation_header_t* header;

    OE_CHECK(oe_safe_add_sizet(sizeof(*header), data_size, total_data_size));

    *total_data = (uint8_t*)oe_malloc(*total_data_size);
    if (*total_data == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    header = (oe_attestation_header_t*)*total_data;
    OE_CHECK(
        oe_fill_attestation_header(format_id, header->data, data_size, header));
    memcpy(header->data, data, data_size);

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_get_evidence(
    const oe_uuid_t* format_id,
    const void* custom_claims,
    size_t custom_claims_size,
    const void* optional_parameters,
    size_t optional_parameters_size,
    uint8_t** evidence_buffer,
    size_t* evidence_buffer_size,
    uint8_t** endorsements_buffer,
    size_t* endorsements_buffer_size)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_plugin_list_node_t* plugin_node = NULL;
    oe_attester_t* plugin = NULL;

    if (!format_id || !evidence_buffer || !evidence_buffer_size ||
        (endorsements_buffer && !endorsements_buffer_size) ||
        (!endorsements_buffer && endorsements_buffer_size))
        OE_RAISE(OE_INVALID_PARAMETER);

    // Find a plugin for attestation type and run its get_evidence.
    plugin_node = oe_attest_find_plugin(attesters, format_id, NULL);
    if (plugin_node == NULL)
        OE_RAISE(OE_NOT_FOUND);

    // Now get the evidence and endorsements (if desired).
    plugin = (oe_attester_t*)plugin_node->plugin;
    OE_CHECK(plugin->get_evidence(
        plugin,
        custom_claims,
        custom_claims_size,
        optional_parameters,
        optional_parameters_size,
        evidence_buffer,
        evidence_buffer_size,
        endorsements_buffer,
        endorsements_buffer_size));

    // Note: plugin is responsible to wrap evidence and endorsements
    // with an attestation header, when format_id requires one.

    result = OE_OK;

done:

    return result;
}

oe_result_t oe_free_evidence(uint8_t* evidence_buffer)
{
    oe_free(evidence_buffer);
    return OE_OK;
}

oe_result_t oe_free_endorsements(uint8_t* evidence_buffer)
{
    oe_free(evidence_buffer);
    return OE_OK;
}

oe_result_t oe_attester_select_format(
    const oe_uuid_t* formats,
    size_t formats_length,
    oe_uuid_t* selected_format)
{
    oe_result_t result = OE_NOT_FOUND;

    if (!formats || !formats_length || !selected_format)
        OE_RAISE(OE_INVALID_PARAMETER);

    for (size_t i = 0; i < formats_length; i++)
    {
        if (oe_attest_find_plugin(attesters, formats + i, NULL))
        {
            memcpy(selected_format, formats + i, sizeof(oe_uuid_t));
            result = OE_OK;
            break;
        }
    }

done:
    return result;
}

oe_result_t oe_find_attester_plugin(
    const oe_uuid_t* format_id,
    oe_attester_t** attester_plugin)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_plugin_list_node_t* plugin_node = NULL;

    if (!format_id || !attester_plugin)
        OE_RAISE(OE_INVALID_PARAMETER);

    plugin_node = oe_attest_find_plugin(attesters, format_id, NULL);
    if (!plugin_node)
        OE_RAISE(OE_NOT_FOUND);

    *attester_plugin = (oe_attester_t*)plugin_node->plugin;

    result = OE_OK;

done:
    return result;
}
