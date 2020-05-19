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

#include "common.h"

#include <openenclave/attestation/verifier.h>
#include <openenclave/internal/plugin.h>
#ifdef OE_BUILD_ENCLAVE
#include <openenclave/attestation/attester.h>
#endif

const char* OE_REQUIRED_CLAIMS[OE_REQUIRED_CLAIMS_COUNT] = {
    OE_CLAIM_ID_VERSION,
    OE_CLAIM_SECURITY_VERSION,
    OE_CLAIM_ATTRIBUTES,
    OE_CLAIM_UNIQUE_ID,
    OE_CLAIM_SIGNER_ID,
    OE_CLAIM_PRODUCT_ID,
    OE_CLAIM_FORMAT_UUID};

const char* OE_OPTIONAL_CLAIMS[OE_OPTIONAL_CLAIMS_COUNT] = {
    OE_CLAIM_VALIDITY_FROM,
    OE_CLAIM_VALIDITY_UNTIL};

/**
 * Header that the OE runtime puts ontop of the attestation plugins.
 */
typedef struct _oe_attestation_header
{
    /* Set to OE_ATTESTATION_HEADER_VERSION. */
    uint32_t version;

    /* UUID to identify format. */
    oe_uuid_t format_id;

    /* Size of evidence/endorsements sent to the plugin. */
    uint64_t data_size;

    /* The actual data */
    uint8_t data[];

    /* data_size bytes that follows the header will be sent to a plugin. */
} oe_attestation_header_t;

// Struct definition to represent the list of plugins.
struct plugin_list_node_t
{
    oe_attestation_role_t* plugin;
    struct plugin_list_node_t* next;
};

// Variables storing the attester and verifier lists.
struct plugin_list_node_t* attesters = NULL;
struct plugin_list_node_t* verifiers = NULL;

static void _print_hex_buf_tail(
    const char* title,
    const uint8_t* buf,
    size_t size,
    size_t tail)
{
    const int max_size = 64;
    size_t offset = 0;
    char* str = NULL;

    // Adjust for printing only the tail
    if (tail && size > tail)
    {
        offset = size - tail;
        size = tail;
    }

    str = (char*)oe_malloc(max_size * 2 + 1);
    if (!str)
    {
        OE_TRACE_ERROR("Out of memory for _print_hex_buf()");
        return;
    }

    if (offset)
        OE_TRACE_VERBOSE(
            "%s[%d ->tail %d]:", title, (int)(size + offset), (int)size);
    else
        OE_TRACE_VERBOSE("%s[%d]:", title, (int)size);

    while (size > 0)
    {
        size_t seg_size = size;
        if (seg_size > max_size)
            seg_size = max_size;
        oe_hex_string(str, seg_size * 2 + 1, buf + offset, seg_size);
        str[seg_size * 2] = '\0';
        OE_TRACE_VERBOSE("%s\n", str);
        size -= seg_size;
        offset += seg_size;
    }
    oe_free(str);
}

static void _print_hex_buf(const char* title, const uint8_t* buf, size_t size)
{
    _print_hex_buf_tail(title, buf, size, 128);
}

// Finds the plugin node with the given ID. If found, the function
// will return the node and store the pointer of the previous node
// in prev (NULL for the head pointer). If not found, the function
// will return NULL.
static struct plugin_list_node_t* _find_plugin(
    struct plugin_list_node_t* head,
    const oe_uuid_t* target_format_id,
    struct plugin_list_node_t** prev)
{
    struct plugin_list_node_t* ret = NULL;
    struct plugin_list_node_t* cur = NULL;

    if (prev)
        *prev = NULL;

    // Find a plugin for attestation type.
    cur = head;
    while (cur)
    {
        if (memcmp(
                &cur->plugin->format_id, target_format_id, sizeof(oe_uuid_t)) ==
            0)
        {
            ret = cur;
            break;
        }
        if (prev)
            *prev = cur;
        cur = cur->next;
    }

    return ret;
}

static oe_result_t _register_plugin(
    struct plugin_list_node_t** list,
    oe_attestation_role_t* plugin,
    const void* config_data,
    size_t config_data_size)
{
    oe_result_t result = OE_UNEXPECTED;
    struct plugin_list_node_t* plugin_node = NULL;

    if (!list || !plugin)
        OE_RAISE(OE_INVALID_PARAMETER);

    plugin_node = _find_plugin(*list, &plugin->format_id, NULL);
    if (plugin_node)
    {
        plugin_node = NULL;
        OE_RAISE(OE_ALREADY_EXISTS);
    }

    plugin_node = (struct plugin_list_node_t*)oe_malloc(sizeof(*plugin_node));
    if (plugin_node == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    // Run the register function for the plugin.
    OE_CHECK(plugin->on_register(plugin, config_data, config_data_size));

    // Add to the plugin list.
    plugin_node->plugin = plugin;
    plugin_node->next = *list;
    *list = plugin_node;
    plugin_node = NULL;

    result = OE_OK;

done:
    if (plugin_node != NULL)
        oe_free(plugin_node);

    return result;
}

static oe_result_t _unregister_plugin(
    struct plugin_list_node_t** list,
    oe_attestation_role_t* plugin)
{
    oe_result_t result = OE_UNEXPECTED;
    struct plugin_list_node_t* prev = NULL;
    struct plugin_list_node_t* cur = NULL;

    if (!list || !plugin)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Find the guid and remove it.
    cur = _find_plugin(*list, &plugin->format_id, &prev);
    if (cur == NULL)
        OE_RAISE(OE_NOT_FOUND);

    if (prev != NULL)
        prev->next = cur->next;
    else
        *list = cur->next;

    // Run the unregister hook for the plugin.
    OE_CHECK(cur->plugin->on_unregister(cur->plugin));

    result = OE_OK;

done:
    oe_free(cur);
    return result;
}

#ifdef OE_BUILD_ENCLAVE

oe_result_t oe_register_attester_plugin(
    oe_attester_t* plugin,
    const void* config_data,
    size_t config_data_size)
{
    return _register_plugin(
        &attesters,
        (oe_attestation_role_t*)plugin,
        config_data,
        config_data_size);
}

oe_result_t oe_unregister_attester_plugin(oe_attester_t* plugin)
{
    return _unregister_plugin(&attesters, (oe_attestation_role_t*)plugin);
}

#endif

oe_result_t oe_register_verifier_plugin(
    oe_verifier_t* plugin,
    const void* config_data,
    size_t config_data_size)
{
    return _register_plugin(
        &verifiers,
        (oe_attestation_role_t*)plugin,
        config_data,
        config_data_size);
}

oe_result_t oe_unregister_verifier_plugin(oe_verifier_t* plugin)
{
    return _unregister_plugin(&verifiers, (oe_attestation_role_t*)plugin);
}

#ifdef OE_BUILD_ENCLAVE
static oe_result_t _wrap_with_header(
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
    header->version = OE_ATTESTATION_HEADER_VERSION;
    header->format_id = *format_id;
    header->data_size = data_size;
    memcpy(header->data, data, data_size);

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_get_evidence(
    const oe_uuid_t* format_id,
    const oe_claim_t* custom_claims,
    size_t custom_claims_length,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t** evidence_buffer,
    size_t* evidence_buffer_size,
    uint8_t** endorsements_buffer,
    size_t* endorsements_buffer_size)
{
    oe_result_t result = OE_UNEXPECTED;
    struct plugin_list_node_t* plugin_node = NULL;
    oe_attester_t* plugin = NULL;
    uint8_t* plugin_evidence = NULL;
    size_t plugin_evidence_size = 0;
    uint8_t* plugin_endorsements = NULL;
    size_t plugin_endorsements_size = 0;
    uint8_t* total_evidence_buf = NULL;
    size_t total_evidence_size = 0;
    uint8_t* total_endorsements_buf = NULL;
    size_t total_endorsements_size = 0;

    if (!format_id || !evidence_buffer || !evidence_buffer_size ||
        (endorsements_buffer && !endorsements_buffer_size) ||
        (!endorsements_buffer && endorsements_buffer_size))
        OE_RAISE(OE_INVALID_PARAMETER);

    // Find a plugin for attestation type and run its get_evidence.
    plugin_node = _find_plugin(attesters, format_id, NULL);
    if (plugin_node == NULL)
        OE_RAISE(OE_NOT_FOUND);

    // Now get the evidence and endorsements (if desired).
    plugin = (oe_attester_t*)plugin_node->plugin;
    OE_CHECK(plugin->get_evidence(
        plugin,
        custom_claims,
        custom_claims_length,
        opt_params,
        opt_params_size,
        &plugin_evidence,
        &plugin_evidence_size,
        endorsements_buffer ? &plugin_endorsements : NULL,
        endorsements_buffer ? &plugin_endorsements_size : NULL));

    // Wrap the attestation header around the evidence.
    OE_CHECK(_wrap_with_header(
        format_id,
        plugin_evidence,
        plugin_evidence_size,
        &total_evidence_buf,
        &total_evidence_size));

    if (endorsements_buffer)
    {
        OE_CHECK(_wrap_with_header(
            format_id,
            plugin_endorsements,
            plugin_endorsements_size,
            &total_endorsements_buf,
            &total_endorsements_size));
    }

    // Finally, set the out parameters.
    *evidence_buffer = total_evidence_buf;
    *evidence_buffer_size = total_evidence_size;
    total_evidence_buf = NULL;

    _print_hex_buf(
        "oe_get_evidence() generated evidence",
        (uint8_t*)*evidence_buffer,
        *evidence_buffer_size);

    if (endorsements_buffer)
    {
        *endorsements_buffer = total_endorsements_buf;
        *endorsements_buffer_size = total_endorsements_size;
        total_endorsements_buf = NULL;
    }

    result = OE_OK;

done:
    if (plugin && plugin_evidence)
    {
        plugin->free_evidence(plugin, plugin_evidence);
        if (plugin_endorsements)
            plugin->free_endorsements(plugin, plugin_endorsements);
    }
    if (total_evidence_buf != NULL)
        oe_free(total_evidence_buf);
    if (total_endorsements_buf != NULL)
        oe_free(total_endorsements_buf);
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
#endif

static bool _check_claims(const oe_claim_t* claims, size_t claims_length)
{
    for (size_t i = 0; i < OE_REQUIRED_CLAIMS_COUNT; i++)
    {
        bool found = false;

        for (size_t j = 0; j < claims_length && !found; j++)
        {
            if (oe_strcmp(OE_REQUIRED_CLAIMS[i], claims[j].name) == 0)
            {
                found = true;
            }
        }

        if (!found)
            return false;
    }
    return true;
}

oe_result_t oe_verify_evidence(
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
    struct plugin_list_node_t* plugin_node;
    oe_verifier_t* verifier;
    oe_attestation_header_t* evidence =
        (oe_attestation_header_t*)evidence_buffer;
    oe_attestation_header_t* endorsements =
        (oe_attestation_header_t*)endorsements_buffer;

    if (!evidence_buffer || evidence_buffer_size < sizeof(*evidence) ||
        (endorsements_buffer &&
         endorsements_buffer_size < sizeof(*endorsements)))
        OE_RAISE(OE_INVALID_PARAMETER);

    _print_hex_buf(
        "oe_verify_evidence() got evidence",
        (uint8_t*)evidence_buffer,
        evidence_buffer_size);

    plugin_node = _find_plugin(verifiers, &evidence->format_id, NULL);
    if (plugin_node == NULL)
        OE_RAISE(OE_NOT_FOUND);

    if (endorsements && memcmp(
                            &evidence->format_id,
                            &endorsements->format_id,
                            sizeof(evidence->format_id)) != 0)
        OE_RAISE(OE_CONSTRAINT_FAILED);

    verifier = (oe_verifier_t*)plugin_node->plugin;
    OE_CHECK(verifier->verify_evidence(
        verifier,
        evidence->data,
        evidence->data_size,
        endorsements ? endorsements->data : NULL,
        endorsements ? endorsements->data_size : 0,
        policies,
        policies_size,
        claims,
        claims_length));

    if (!_check_claims(*claims, *claims_length))
    {
        verifier->free_claims(verifier, *claims, *claims_length);
        *claims = NULL;
        *claims_length = 0;
        OE_RAISE(OE_CONSTRAINT_FAILED);
    }

    result = OE_OK;

done:
    return result;
}

static oe_result_t _get_uuid(
    const oe_claim_t* claims,
    size_t claims_length,
    oe_uuid_t* uuid)
{
    for (size_t i = 0; i < claims_length; i++)
    {
        if (oe_strcmp(claims[i].name, OE_CLAIM_FORMAT_UUID) == 0)
        {
            if (claims[i].value_size != sizeof(oe_uuid_t))
                return OE_CONSTRAINT_FAILED;

            *uuid = *((oe_uuid_t*)claims[i].value);
            return OE_OK;
        }
    }
    return OE_NOT_FOUND;
}

oe_result_t oe_free_claims(oe_claim_t* claims, size_t claims_length)
{
    oe_uuid_t uuid;
    oe_result_t result = OE_UNEXPECTED;
    struct plugin_list_node_t* plugin_node;
    oe_verifier_t* verifier;

    if (!claims)
        return OE_OK;

    OE_CHECK(_get_uuid(claims, claims_length, &uuid));

    plugin_node = _find_plugin(verifiers, &uuid, NULL);
    if (plugin_node == NULL)
        OE_RAISE(OE_NOT_FOUND);

    verifier = (oe_verifier_t*)plugin_node->plugin;
    OE_CHECK(verifier->free_claims(verifier, claims, claims_length));

    result = OE_OK;

done:
    return result;
}

// Count the number of plugins in the input list
static size_t _count_plugins(struct plugin_list_node_t* head)
{
    struct plugin_list_node_t* cur = head;
    size_t count = 0;
    while (cur)
    {
        cur = cur->next;
        count++;
    }
    return count;
}

#ifdef OE_BUILD_ENCLAVE
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
        if (_find_plugin(attesters, formats + i, NULL))
        {
            memcpy(selected_format, formats + i, sizeof(oe_uuid_t));
            result = OE_OK;
            break;
        }
    }

done:
    return result;
}
#endif

oe_result_t oe_verifier_get_formats(oe_uuid_t** formats, size_t* formats_length)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t count = 0;
    oe_uuid_t* formats_buf = NULL;

    if (!formats || !formats_length)
        OE_RAISE(OE_INVALID_PARAMETER);

    count = _count_plugins(verifiers);
    if (!count)
    {
        *formats = NULL;
        *formats_length = 0;
        result = OE_OK;
    }
    else
    {
        struct plugin_list_node_t* cur = NULL;
        size_t idx = 0;

        formats_buf = (oe_uuid_t*)oe_malloc(count * sizeof(oe_uuid_t));
        if (!formats_buf)
            OE_RAISE(OE_OUT_OF_MEMORY);

        cur = verifiers;
        idx = 0;
        while (cur && idx < count)
        {
            memcpy(
                formats_buf + idx, &cur->plugin->format_id, sizeof(oe_uuid_t));
            cur = cur->next;
            idx++;
        }

        // No plugin is expected to be added or removed
        // while oe_verifier_get_formats() runs.
        if (idx < count || cur)
            OE_RAISE(OE_UNEXPECTED);

        *formats = formats_buf;
        *formats_length = count;
        formats_buf = NULL;
        result = OE_OK;
    }

done:
    if (formats_buf)
        oe_free(formats_buf);
    return result;
}

oe_result_t oe_verifier_free_formats(oe_uuid_t* formats)
{
    oe_free(formats);
    return OE_OK;
}

oe_result_t oe_verifier_get_format_settings(
    const oe_uuid_t* format,
    uint8_t** settings,
    size_t* settings_size)
{
    oe_result_t result = OE_UNEXPECTED;
    struct plugin_list_node_t* plugin_node = NULL;
    oe_verifier_t* plugin = NULL;

    if (!format || !settings || !settings_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    plugin_node = _find_plugin(verifiers, format, NULL);
    if (!plugin_node)
        OE_RAISE(OE_NOT_FOUND);

    plugin = (oe_verifier_t*)plugin_node->plugin;
    OE_CHECK(plugin->get_format_settings(plugin, settings, settings_size));

done:
    return result;
}

oe_result_t oe_verifier_free_format_settings(uint8_t* settings)
{
    oe_free(settings);
    return OE_OK;
}

#ifdef OE_BUILD_ENCLAVE

oe_result_t oe_find_attester_plugin(
    const oe_uuid_t* format_id,
    oe_attester_t** attester_plugin)
{
    oe_result_t result = OE_UNEXPECTED;
    struct plugin_list_node_t* plugin_node = NULL;

    if (!format_id || !attester_plugin)
        OE_RAISE(OE_INVALID_PARAMETER);

    plugin_node = _find_plugin(attesters, format_id, NULL);
    if (!plugin_node)
        OE_RAISE(OE_NOT_FOUND);

    *attester_plugin = (oe_attester_t*)plugin_node->plugin;

    result = OE_OK;

done:
    return result;
}

#endif

oe_result_t oe_find_verifier_plugin(
    const oe_uuid_t* format_id,
    oe_verifier_t** verifier_plugin)
{
    oe_result_t result = OE_UNEXPECTED;
    struct plugin_list_node_t* plugin_node = NULL;

    if (!format_id || !verifier_plugin)
        OE_RAISE(OE_INVALID_PARAMETER);

    plugin_node = _find_plugin(verifiers, format_id, NULL);
    if (!plugin_node)
        OE_RAISE(OE_NOT_FOUND);

    *verifier_plugin = (oe_verifier_t*)plugin_node->plugin;

    result = OE_OK;

done:
    return result;
}
