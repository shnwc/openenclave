// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#if defined(OE_LINK_SGX_DCAP_QL)

#include "sgxquote.h"
#include <openenclave/internal/defs.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgx/plugin.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/trace.h>
#include <sgx_dcap_ql_wrapper.h>
#include <sgx_quote_3.h>
#include <string.h>
#include "../../common/oe_host_stdlib.h"

#if __has_include(<sgx_uae_quote_ex.h>)
#define OE_LINK_SGX_QUOTE_EX
#include <sgx_uae_quote_ex.h>
#include "../hostthread.h"
#include "sgxquote_ex.h"
#endif

// Check consistency with OE definition.
OE_STATIC_ASSERT(sizeof(sgx_target_info_t) == 512);
OE_STATIC_ASSERT(sizeof(sgx_report_t) == 432);

static const oe_uuid_t _ecdsa_p256_uuid = {OE_FORMAT_UUID_SGX_ECDSA_P256};

#ifdef OE_LINK_SGX_QUOTE_EX

OE_STATIC_ASSERT(sizeof(sgx_att_key_id_ext_t) == sizeof(sgx_att_key_id_t));

// Redefine some constants in <sgx_quote_3.h> to be more meaningful
#define SGX_QL_ALG_EPID_UNLINKABLE SGX_QL_ALG_EPID
#define SGX_QL_ALG_EPID_LINKABLE SGX_QL_ALG_RESERVED_1

static oe_sgx_quote_ex_library_t _quote_ex_library = {0};
static const oe_uuid_t _unknown_uuid = {OE_FORMAT_UUID_SGX_UNKNOWN};
static const oe_uuid_t _ecdsa_p384_uuid = {OE_FORMAT_UUID_SGX_ECDSA_P384};
static const oe_uuid_t _epid_linkable_uuid = {OE_FORMAT_UUID_SGX_EPID_LINKABLE};
static const oe_uuid_t _epid_unlinkable_uuid = {
    OE_FORMAT_UUID_SGX_EPID_UNLINKABLE};

static sgx_att_key_id_ext_t* _format_id_to_key_id(const oe_uuid_t* format_id)
{
    if (!format_id)
        return NULL;

    for (size_t i = 0; i < _quote_ex_library.key_id_count; i++)
    {
        if (!_quote_ex_library.mapped[i])
            continue;

        if (!memcmp(format_id, _quote_ex_library.uuid + i, sizeof(oe_uuid_t)))
            return _quote_ex_library.sgx_key_id + i;
    }

    return NULL;
}

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
        OE_TRACE_INFO(
            "%s[%d ->tail %d]:", title, (int)(size + offset), (int)size);
    else
        OE_TRACE_INFO("%s[%d]:", title, (int)size);

    while (size > 0)
    {
        size_t seg_size = size;
        if (seg_size > max_size)
            seg_size = max_size;
        oe_hex_string(str, seg_size * 2 + 1, buf + offset, seg_size);
        str[seg_size * 2] = '\0';
        OE_TRACE_INFO("%s\n", str);
        size -= seg_size;
        offset += seg_size;
    }
    oe_free(str);
}

#endif // OE_LINK_SGX_QUOTE_EX

oe_result_t oe_sgx_qe_get_target_info(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t* target_info)
{
    oe_result_t result = OE_UNEXPECTED;
    quote3_error_t err = SGX_QL_ERROR_UNEXPECTED;

    if (!format_id || !target_info)
        OE_RAISE(OE_INVALID_PARAMETER);

#ifdef OE_LINK_SGX_QUOTE_EX

    if (oe_initialize_quote_ex_library() == OE_OK)
    {
        sgx_status_t status = SGX_ERROR_UNEXPECTED;
        sgx_att_key_id_ext_t updated_key_id = {{0}};
        size_t tmp_size = 0;
        uint8_t* tmp_buffer = NULL;
        sgx_target_info_t tmp_target_info;

        sgx_att_key_id_ext_t* key_id = _format_id_to_key_id(format_id);
        if (!key_id)
            OE_RAISE(OE_UNSUPPORTED);

        // Update key ID with input SP ID for EPID quoting
        memcpy(&updated_key_id, key_id, sizeof(*key_id));
        if (key_id->base.algorithm_id == SGX_QL_ALG_EPID_LINKABLE ||
            key_id->base.algorithm_id == SGX_QL_ALG_EPID_UNLINKABLE)
        {
            if (opt_params && opt_params_size == sizeof(key_id->spid))
                memcpy(updated_key_id.spid, opt_params, opt_params_size);
        }

        status = _quote_ex_library.sgx_init_quote_ex(
            (sgx_att_key_id_t*)&updated_key_id,
            &tmp_target_info,
            &tmp_size,
            NULL);

        if (status != SGX_SUCCESS)
            OE_RAISE_MSG(
                OE_PLATFORM_ERROR,
                "sgx_init_quote_ex(NULL) returned 0x%x\n",
                status);

        tmp_buffer = (uint8_t*)oe_malloc(tmp_size);
        OE_TEST(tmp_buffer);

        status = _quote_ex_library.sgx_init_quote_ex(
            (sgx_att_key_id_t*)&updated_key_id,
            &tmp_target_info,
            &tmp_size,
            tmp_buffer);
        oe_free(tmp_buffer);

        if (status != SGX_SUCCESS)
            OE_RAISE_MSG(
                OE_PLATFORM_ERROR,
                "sgx_init_quote_ex(tmp_buffer) returned 0x%x\n",
                status);

        memcpy(target_info, &tmp_target_info, sizeof(sgx_target_info_t));

        result = OE_OK;
        goto done;
    }

#else // OE_LINK_SGX_QUOTE_EX

    OE_UNUSED(opt_params);
    OE_UNUSED(opt_params_size);

#endif // OE_LINK_SGX_QUOTE_EX

    err = sgx_qe_get_target_info((sgx_target_info_t*)target_info);

    if (err != SGX_QL_SUCCESS)
        OE_RAISE_MSG(OE_PLATFORM_ERROR, "quote3_error_t=0x%x\n", err);

    result = OE_OK;
done:
    return result;
}

oe_result_t oe_sgx_qe_get_quote_size(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    size_t* quote_size)
{
    oe_result_t result = OE_UNEXPECTED;
    uint32_t local_quote_size = (uint32_t)*quote_size;
    quote3_error_t err = SGX_QL_ERROR_UNEXPECTED;

    if (!format_id || !quote_size)
        OE_RAISE(OE_INVALID_PARAMETER);

#ifdef OE_LINK_SGX_QUOTE_EX

    if (oe_initialize_quote_ex_library() == OE_OK)
    {
        sgx_status_t status = SGX_ERROR_UNEXPECTED;
        sgx_att_key_id_ext_t updated_key_id = {{0}};

        sgx_att_key_id_ext_t* key_id = _format_id_to_key_id(format_id);
        if (!key_id)
            OE_RAISE(OE_UNSUPPORTED);

        // Update key ID with input SP ID for EPID quoting
        memcpy(&updated_key_id, key_id, sizeof(*key_id));
        if (key_id->base.algorithm_id == SGX_QL_ALG_EPID_LINKABLE ||
            key_id->base.algorithm_id == SGX_QL_ALG_EPID_UNLINKABLE)
        {
            if (opt_params && opt_params_size == sizeof(key_id->spid))
                memcpy(updated_key_id.spid, opt_params, opt_params_size);
        }

        status = _quote_ex_library.sgx_get_quote_size_ex(
            (const sgx_att_key_id_t*)&updated_key_id, &local_quote_size);

        if (status != SGX_SUCCESS)
            OE_RAISE_MSG(
                OE_PLATFORM_ERROR,
                "sgx_get_quote_size_ex() returned 0x%x\n",
                status);

        OE_TRACE_INFO("local_quote_size = %lu\n", local_quote_size);

        *quote_size = local_quote_size;
        result = OE_OK;
        goto done;
    }

#else // OE_LINK_SGX_QUOTE_EX

    OE_UNUSED(opt_params);
    OE_UNUSED(opt_params_size);

#endif // OE_LINK_SGX_QUOTE_EX

    err = sgx_qe_get_quote_size(&local_quote_size);

    if (err != SGX_QL_SUCCESS)
        OE_RAISE_MSG(OE_PLATFORM_ERROR, "quote3_error_t=0x%x\n", err);

    *quote_size = local_quote_size;
    result = OE_OK;
done:
    return result;
}

oe_result_t oe_sgx_qe_get_quote(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t* report,
    size_t quote_size,
    uint8_t* quote)
{
    oe_result_t result = OE_UNEXPECTED;
    uint32_t local_quote_size = (uint32_t)quote_size;
    quote3_error_t err = SGX_QL_ERROR_UNEXPECTED;

    if (!format_id || !report || !quote || !quote_size ||
        quote_size > OE_MAX_UINT32)
        OE_RAISE(OE_INVALID_PARAMETER);

#ifdef OE_LINK_SGX_QUOTE_EX

    if (oe_initialize_quote_ex_library() == OE_OK)
    {
        sgx_status_t status = SGX_ERROR_UNEXPECTED;
        sgx_att_key_id_ext_t updated_key_id = {{0}};

        sgx_att_key_id_ext_t* key_id = _format_id_to_key_id(format_id);
        if (!key_id)
            OE_RAISE(OE_UNSUPPORTED);

        // Update key ID with input SP ID for EPID quoting
        memcpy(&updated_key_id, key_id, sizeof(*key_id));
        if (key_id->base.algorithm_id == SGX_QL_ALG_EPID_LINKABLE ||
            key_id->base.algorithm_id == SGX_QL_ALG_EPID_UNLINKABLE)
        {
            if (opt_params && opt_params_size == sizeof(key_id->spid))
                memcpy(updated_key_id.spid, opt_params, opt_params_size);
        }

        status = _quote_ex_library.sgx_get_quote_ex(
            (const sgx_report_t*)report,
            (const sgx_att_key_id_t*)&updated_key_id,
            NULL,
            quote,
            local_quote_size);

        if (status != SGX_SUCCESS)
            OE_RAISE_MSG(
                OE_PLATFORM_ERROR,
                "sgx_get_quote_ex() returned 0x%x\n",
                status);

        OE_TRACE_INFO(
            "quote_ex got quote for algorithm_id=%d\n",
            key_id->base.algorithm_id);

        result = OE_OK;
        goto done;
    }

#else // OE_LINK_SGX_QUOTE_EX

    OE_UNUSED(opt_params);
    OE_UNUSED(opt_params_size);

#endif // OE_LINK_SGX_QUOTE_EX

    err = sgx_qe_get_quote((sgx_report_t*)report, local_quote_size, quote);
    if (err != SGX_QL_SUCCESS)
        OE_RAISE_MSG(OE_PLATFORM_ERROR, "quote3_error_t=0x%x\n", err);
    OE_TRACE_INFO("quote_size=%d", local_quote_size);

    result = OE_OK;
done:
    return result;
}

oe_result_t oe_sgx_get_supported_attester_format_ids(
    void* format_ids,
    size_t* format_ids_size)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!format_ids_size)
        OE_RAISE(OE_INVALID_PARAMETER);

#ifdef OE_LINK_SGX_QUOTE_EX

    if (oe_initialize_quote_ex_library() == OE_OK)
    {
        size_t count = _quote_ex_library.mapped_key_id_count;
        size_t index = 0;

        if (count &&
            (!format_ids || *format_ids_size < sizeof(oe_uuid_t) * count))
        {
            *format_ids_size = sizeof(oe_uuid_t) * count;
            OE_RAISE(OE_BUFFER_TOO_SMALL);
        }

        for (size_t i = 0; i < _quote_ex_library.key_id_count; i++)
        {
            // Skip the entry if it was not mapped.
            if (!_quote_ex_library.mapped[i])
                continue;

            memcpy(
                ((uint8_t*)format_ids) + sizeof(oe_uuid_t) * index,
                _quote_ex_library.uuid + i,
                sizeof(oe_uuid_t));
            index++;
        }

        OE_TEST(index == count);

        *format_ids_size = sizeof(oe_uuid_t) * count;

        OE_TRACE_INFO("quote_ex got %lu format IDs\n", count);
        _print_hex_buf_tail("format_ids: ", format_ids, *format_ids_size, 0);
        _print_hex_buf_tail(
            "_quote_ex_library.uuid: ",
            (uint8_t*)_quote_ex_library.uuid,
            *format_ids_size,
            0);

        result = OE_OK;
        goto done;
    }

#endif // OE_LINK_SGX_QUOTE_EX

    // Case when DCAP is used
    if (!format_ids || *format_ids_size < sizeof(oe_uuid_t))
    {
        *format_ids_size = sizeof(oe_uuid_t);
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }
    memcpy(format_ids, &_ecdsa_p256_uuid, sizeof(oe_uuid_t));
    *format_ids_size = sizeof(oe_uuid_t);

    OE_TRACE_INFO("DCAP only supports ECDSA_P256\n");
    result = OE_OK;

done:
    return result;
}

#ifdef OE_LINK_SGX_QUOTE_EX

static void _load_quote_ex_library_once(void)
{
    bool* tmp_mapped = NULL;
    oe_uuid_t* tmp_uuid = NULL;
    sgx_att_key_id_ext_t* tmp_key_id = NULL;
    oe_result_t result = OE_UNEXPECTED;

    if (_quote_ex_library.handle && _quote_ex_library.load_result == OE_OK)
        return;

    oe_load_quote_ex_library(&_quote_ex_library);
    if (_quote_ex_library.load_result == OE_OK)
    {
        uint32_t att_key_id_num = 0;
        uint32_t mapped_key_id_count = 0;
        sgx_status_t status = SGX_ERROR_UNEXPECTED;
        status =
            _quote_ex_library.sgx_get_supported_att_key_id_num(&att_key_id_num);
        if (status != SGX_SUCCESS || att_key_id_num == 0)
        {
            OE_TRACE_ERROR(
                "_load_quote_ex_library_once() "
                "sgx_get_supported_att_key_id_num() status=%d num=%d\n",
                status,
                att_key_id_num);
            OE_RAISE(OE_QUOTE_PROVIDER_CALL_ERROR);
        }

        tmp_mapped = (bool*)oe_malloc(att_key_id_num * sizeof(bool));
        tmp_uuid = (oe_uuid_t*)oe_malloc(att_key_id_num * sizeof(oe_uuid_t));
        tmp_key_id = (sgx_att_key_id_ext_t*)oe_malloc(
            att_key_id_num * sizeof(sgx_att_key_id_ext_t));

        if (!tmp_mapped || !tmp_uuid || !tmp_key_id)
            OE_RAISE(OE_OUT_OF_MEMORY);

        status = _quote_ex_library.sgx_get_supported_att_key_ids(
            tmp_key_id, att_key_id_num);
        if (status != SGX_SUCCESS)
            OE_RAISE_MSG(
                OE_PLATFORM_ERROR,
                "_load_quote_ex_library_once() "
                "sgx_get_supported_att_key_ids() status=%d\n",
                status);

        for (uint32_t i = 0; i < att_key_id_num; i++)
        {
            sgx_att_key_id_ext_t* key = tmp_key_id + i;
            const oe_uuid_t* uuid = NULL;

            OE_TRACE_INFO("algorithm_id=%d", key->base.algorithm_id);

            switch (key->base.algorithm_id)
            {
                case SGX_QL_ALG_EPID_UNLINKABLE:
                    uuid = &_epid_unlinkable_uuid;
                    tmp_mapped[i] = true;
                    mapped_key_id_count++;
                    break;
                case SGX_QL_ALG_EPID_LINKABLE:
                    uuid = &_epid_linkable_uuid;
                    tmp_mapped[i] = true;
                    mapped_key_id_count++;
                    break;
                case SGX_QL_ALG_ECDSA_P256:
                    uuid = &_ecdsa_p256_uuid;
                    tmp_mapped[i] = true;
                    mapped_key_id_count++;
                    break;
                case SGX_QL_ALG_ECDSA_P384:
                    uuid = &_ecdsa_p384_uuid;
                    tmp_mapped[i] = true;
                    mapped_key_id_count++;
                    break;
                default:
                    uuid = &_unknown_uuid;
                    tmp_mapped[i] = false;
                    OE_TRACE_ERROR(
                        "algorithm_id=%d maps to no uuid",
                        key->base.algorithm_id);
                    break;
            }
            memcpy(tmp_uuid + i, uuid, sizeof(oe_uuid_t));
        }

        _quote_ex_library.key_id_count = att_key_id_num;
        _quote_ex_library.mapped_key_id_count = mapped_key_id_count;
        _quote_ex_library.mapped = tmp_mapped;
        _quote_ex_library.uuid = tmp_uuid;
        _quote_ex_library.sgx_key_id = tmp_key_id;
        tmp_mapped = NULL;
        tmp_uuid = NULL;
        tmp_key_id = NULL;

        OE_TRACE_INFO(
            "key_id_count=%lu mapped=%lu\n",
            att_key_id_num,
            mapped_key_id_count);

        result = OE_OK;
    }

done:
    if (tmp_mapped)
    {
        oe_free(tmp_mapped);
        tmp_mapped = NULL;
    }
    if (tmp_uuid)
    {
        oe_free(tmp_uuid);
        tmp_uuid = NULL;
    }
    if (tmp_key_id)
    {
        oe_free(tmp_key_id);
        tmp_key_id = NULL;
    }
    if (_quote_ex_library.load_result == OE_OK)
        _quote_ex_library.load_result = result;

    OE_TRACE_INFO(
        "_load_quote_ex_library_once() result=%s\n",
        oe_result_str(_quote_ex_library.load_result));

    return;
}

oe_result_t oe_initialize_quote_ex_library(void)
{
    static oe_once_type once = OE_H_ONCE_INITIALIZER;
    oe_once(&once, _load_quote_ex_library_once);

    return _quote_ex_library.load_result;
}

#endif // OE_LINK_SGX_QUOTE_EX

#endif // OE_LINK_SGX_DCAP_QL
