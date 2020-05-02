// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_HOST_QUOTE_H
#define _OE_HOST_QUOTE_H

#include <openenclave/bits/report.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include <openenclave/bits/sgx/sgxtypes.h>

OE_EXTERNC_BEGIN

/*
**==============================================================================
**
** sgx_get_quote_size()
**
**==============================================================================
*/

oe_result_t sgx_get_quote_size(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    size_t* quote_size);

/*
**==============================================================================
**
** sgx_get_qetarget_info()
**
**==============================================================================
*/

oe_result_t sgx_get_qetarget_info(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    sgx_target_info_t* target_info);

/*
**==============================================================================
**
** sgx_get_quote()
**
**==============================================================================
*/
oe_result_t sgx_get_quote(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    const sgx_report_t* sgx_report,
    uint8_t* quote,
    size_t* quote_size);

/*
**==============================================================================
**
** sgx_get_supported_attester_format_ids()
**
**==============================================================================
*/
oe_result_t sgx_get_supported_attester_format_ids(
    void* format_ids,
    size_t* format_ids_size);

OE_EXTERNC_END

#endif /* _OE_HOST_QUOTE_H */
