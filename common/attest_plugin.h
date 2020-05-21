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

//#include <openenclave/attestation/verifier.h>
#include <openenclave/internal/plugin.h>

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
typedef struct _plugin_list_node_t
{
    oe_attestation_role_t* plugin;
    struct _plugin_list_node_t* next;
} oe_plugin_list_node_t;

// Finds the plugin node with the given ID. If found, the function
// will return the node and store the pointer of the previous node
// in prev (NULL for the head pointer). If not found, the function
// will return NULL.
oe_plugin_list_node_t* oe_attest_find_plugin(
    oe_plugin_list_node_t* head,
    const oe_uuid_t* target_format_id,
    oe_plugin_list_node_t** prev);

oe_result_t oe_attest_register_plugin(
    oe_plugin_list_node_t** list,
    oe_attestation_role_t* plugin,
    const void* configuration_data,
    size_t configuration_data_size);

oe_result_t oe_attest_unregister_plugin(
    oe_plugin_list_node_t** list,
    oe_attestation_role_t* plugin);
