# Attestation: OE SDK Integration with Intel® SGX SDK quote-ex Library for Support of New SGX Evidence Formats

This design document proposes an extension of the OE SDK implementation for integration with Intel® SGX SDK quote-ex library, for support of generation of SGX evidence in new formats such as Enhanced Privacy ID (EPID).

# Motivation

Existing implementation of OE SDK SGX attestation, based on Intel® SGX SDK Data Center Attestation Primitives (DCAP) quote generation library (simply called the DCAP library), only supports generation of evidence in a single SGX ECDSA-p256 format.

On some SGX platforms, other evidence formats - including those based on Enhanced Privacy ID (EPID), are supported and preferred by some application solutions. Generation of evidence in these formats is supported by the Intel® SGX SDK provides a library package, libsgx-quote-ex (or simply called quote-ex).

# User Experience

The proposed extension only impacts the internal implementation of the OE SDK attestation software stack. It does not result in any change in the OE SDK API as described in [PR #2621](https://github.com/openenclave/openenclave/pull/2621). With the integration of the quote-ex library, an attester application enclave call to OE SDK API `oe_sgx_get_attester_plugins()` returns the list of all SGX evidence formats that can be generated for the calling enclave instance.

Integration of the quote-ex library depends on the installation of the Intel® SGX SDK quote-ex library and its dependencies, and proper configuration of the components and their access to dependent backend services. Details for the installation and configuration are outside of the scope of this document.

# Specification

## Existing OE SDK Implementation

### Evidence Format Enumeration and Plugin Registration

Existing OE SDK implementation based on the DCAP library only supports generation of evidence in a single SGX ECDSA-p256 format, so there is no need for enumeration of supported evidence formats. As implemented in code file `enclave/sgx/attester.c`, a single attester plugin is created and registered for the SGX ECDSA-p256 evidence format.
- Note: in the current OE SDK implementation, the UUID for the ECDSA-p256 evidence format is still called `OE_SGX_PLUGIN_UUID`.

### Implementation of OE SDK API `oe_get_evidence()`

The implementation of OE SDK API `oe_get_evidence()`, in code file `common/attest_plugin.c`, searches for a plugin that supports the requested evidence format, and invokes the `get_evidence()` entry point of the selected plugin.

The SGX ECDSA-p256 plugin is implemented in code file `enclave/sgx/attester.c` and other relevant enclave-side and host-side code files, called enclave-side and host-side plugin libraries in this document. The enclave-side plugin library interacts with the host-side plugin library via OCALLs defined in interface definition file `common/sgx/sgx.edl`. For SGX ECDSA-p256 evidence generation, there are 2 OCALLs: 

- `oe_get_qetarget_info_ocall(sgx_target_info_t* target_info)`
    - Returns the SGX Quoting Enclave (QE) target information.
- `oe_get_quote_ocall(const sgx_report_t* sgx_report, void* quote, size_t quote_size, size_t* quote_size_out)`
    - Generates an ECDSA-p256 quote and returns in the caller-supplied buffer, or returns the needed buffer size if the supplied buffer is missing or not large enough.

Since only a single evidence format is supported and this format does not require any optional parameter. These OCALLs don't pass either the evidence format ID or optional parameters.

The host-side plugin library implements the OCALL, as in code file `host/sgx/ocalls.c` and other relevant code files. As defined in the main `cmake` configuration file `CMakeLists.txt` in the OE SDK top directory, the DCAP library is linked to the OE SDK host-side plugin library. The DCAP library provides following 3 APIs in support of the above two OCALLs, as defined in its [header file](https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/QuoteGeneration/quote_wrapper/ql/inc/sgx_dcap_ql_wrapper.h).

- `sgx_qe_get_target_info(sgx_target_info_t *p_qe_target_info)`
    - Returns the SGX Quoting Enclave (QE) target information.
- `sgx_qe_get_quote_size(uint32_t *p_quote_size)`
    - Returns the size of the buffer needed to hold the SGX ECDSA quote to be generated.
- `sgx_qe_get_quote(const sgx_report_t *p_app_report, uint32_t quote_size, uint8_t *p_quote)`
    - Generates an SGX ECDSA quote and returns it in the caller-supplied buffer.

### Project Compile and Linking

As defined in `cmake` configuration file `host/CMakeLists.txt`, for OE SDK built on an SGX platform, the host-side plugin library code is linked into the DCAP static library.

## Proposed Changes

### quote-ex Library API

For generation of SGX evidence in ECDSA and EPID formats, the SGX quote-ex library has the relevant API defined in its [header file](https://github.com/intel/linux-sgx/blob/master/common/inc/sgx_uae_quote_ex.h):

- `sgx_get_supported_att_key_ids(sgx_att_key_id_ext_t *p_att_key_id_list, uint32_t *p_att_key_id_list_size)`
    - Returns the list of supported attestation key IDs (which can be mapped to OE SDK evidence formats) on the current platform.
    - Note: this function is not yet available in the current release, but will be added in a future release.
- `sgx_init_quote_ex(const sgx_att_key_id_t* p_att_key_id, sgx_target_info_t *p_qe_target_info, size_t* p_pub_key_id_size, uint8_t* p_pub_key_id);`
    - Returns the SGX Quoting Enclave (QE) target information for the given attestation key ID.
- `sgx_get_quote_size_ex(const sgx_att_key_id_t *p_att_key_id, uint32_t* p_quote_size)`
    - Returns the size of the buffer needed to hold the quote to be generated for the given attestation key ID.
- `sgx_get_quote_ex(const sgx_report_t *p_app_report, const sgx_att_key_id_t *p_att_key_id,sgx_qe_report_info_t *p_qe_report_info, uint8_t *p_quote, uint32_t quote_size)`
    - Generates a quote for the given attestation key ID, and returns it in the call-supplied buffer.

As compared to the DCAP library API, the quote-ex library API supports enumeration of supported evidence formats (called attestation key IDs in the API). Otherwise the quote-ex API is similar to the DCAP API, except that every function takes an input attestation key ID in its parameter list.

### Host-side Plugin Library Dynamic Load of quote-ex or DCAP library

An SGX platform can have either one of the quote-ex or DCAP library, or both libraries installed. When both libraries are installed, the quote-ex library should take precedence, since it supports a super set of evidence formats. 

The OE SDK host-side plugin library is updated to dynamically detect the presence of the two libraries, load one of them, and record the entry points of the loaded library for invocation in the flows described below.

### Support of SGX Evidence Formats Enumeration

the SGX plugin code file `enclave/sgx/attester.c` implements the OE SDK API `oe_sgx_get_attester_plugins()`: enumerates all supported SGX evidence formats, creates a list of attester plugins for them, and returns the created list to the caller.

For SGX evidence formats enumeration, a new OCALL is added to interface definition file in `common/sgx/sgx.edl` and implemented in the host-side SGX plugin library:

- `oe_get_supported_sgx_attester_format_ids(oe_uuid_t** format_ids, size_t* format_ids_length)`
    - Note: this OCALL returns a list of supported evidence format IDs in a dynamically allocated buffer. The caller should reclaim the buffer after consumption of the list.

In the implementation of this OCALL by the host-side SGX plugin library:

- If the DCAP library is loaded, a list with a single format ID for ECDSA-p256 is return.
- Otherwise if the quote-ex library is loaded, its API `sgx_get_supported_att_key_ids()` is invoked, and the returned list of attestation key IDs is converted to a list of OE SDK evidence format IDs. 
    - Note: the details of the mapping between OE SDK evidence format IDs and SGX quote-ex library attestation key IDs are still to-be-defined.

### Updated Implementation of OE SDK API oe_get_evidence()

The OCALLs for SGX evidence generation are extended to include the requested evidence format ID and its companion optional parameters, as shown below:

- `oe_get_qetarget_info_ocall(const oe_uuid_t* format_id, const void* opt_params, size_t opt_params_size, sgx_target_info_t* target_info)`
    - Returns the SGX Quoting Enclave (QE) target information for the given evidence format ID and its optional parameters.
- `oe_get_quote_ocall(const oe_uuid_t* format_id, const void* opt_params, size_t opt_params_size, const sgx_report_t* sgx_report, void* quote, size_t quote_size, size_t* quote_size_out)`
    - Generates a quote for the given evidence format ID and its optional parameters, and returns it in the caller-supplied buffer.
    - But if the supplied buffer is missing or not large enough, it only returns the needed buffer size.

In the host-side SGX plugin library implementation:

- If the DCAP library is loaded, only evidence format of ECDSA-p256 is accepted, and the corresponding DCAP API entry point functions are invoked to get the QE target info or to generate the quote.
- If the quote-ex library is loaded, the host-side library maps the input evidence format ID to the corresponding SGX attestation key ID and applies the optional parameter to the key ID structure (if any), and invokes the quote-ex API entry point functions to get the QE target info or to generate the quote.

# Alternates

The SGX quote-ex library is the only option available to support SGX evidence formats other than ECDSA-p256.

# Authors

- Name: Shanwei Cen
    - email: Shanwei.cen@intel.com
    - github user name: shnwc
- Name: Yen Lee
    - email: yenlee@microsoft.com
    - github username: yentsanglee
