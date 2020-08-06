Attestation: OE SDK Integration with Intel® SGX DCAP Quote Verification Library for SGX Evidence verification
====

This design document proposes an extension of the OE SDK implementation
for integration with the Intel® SGX Data Center Attestation Primitives (DCAP) Quote Verification Library (QVL), for support of
evidence verification in ECDSA-p256 formats.

# Motivation

Existing OE SDK has it's own logic for SGX ECDSA quote verification.
As implemented in code file `common/sgx/quote.c`, verification code 
has complex logic for SGX cert chain verification and Enclave Identity 
verification, including x509 parser, cert revocation checking, JSON and etc. 
Also it would use some 3rd party codes, such as mbedtls.

As all the verification logics would be built into verifer's enclave,
which means OE SDK introduce a big TCB for verifier's enclave. Once
there is a CVE in verification logic, including 3rd party component.
Verifer needs to upgrade and rebuild their enclave.

Do you see if the current implementation being incomplete? e.g. function
`_validate_sgx_quote()` in `common/sgx/quote.c` only checks quote version number.

# User Experience

The proposed extension only changes the internal implementation of the OE SDK
attestation software stack. It does not impact the
[OE SDK attestation API](https://github.com/openenclave/openenclave/pull/2949).
If SGX verifier plugin is used, with the integration of SGX QVL, a verifier's
call to OE SDK API `oe_verify_evidence()` would triggers quote verification by
invoking Intel® SGX DCAP (QVL) or Quote Verification Enclave (QvE), depending on
whether the call is from the enclave side or the host side.

Integration of the quote verification library depends on the installation of the
Intel® SGX DCAP packages (please list the individual packages) and its dependencies,
as well as proper configuration of the components and their access to
dependent backend services (which backend service are used? In OE SDK,
before quote verification, the complete PCK cert chain is already retrieved).
Details for the DCAP quote verification library installation
and configuration are outside the scope of this document.

# Specification

## Existing OE SDK Implementation

### Implementation of SGX ECDSA-p256 verifier plugin

The current implementation verifier plugin searchs for a verifier plugin that
supports the requested evidence format, and invoke the `verify_evidence()` or `verify_report()`
entry point of the selected plugin.

The SGX ECDSA-p256 verifier plugin is implemented in code file
`enclave/sgx/report.c`, `common/sgx/verifier.c` and relevant enclave-side code file 
`common/sgx/quote.c`. The same source tree implements both the enclave-side and
host-side verifier plugins.

There are 2 different scenarios in current SGX ECDSA quote verification:
- Scenario 1 - Call `oe_verify_report()` to verify SGX remote report (aka SGX quote)
- Scenario 2 - Call `oe_verify_evidence()` to verify evidence in format `OE_FORMAT_UUID_SGX_ECDSA_P256`.

Based on design doc [Remote Attestation Collaterals](https://github.com/openenclave/openenclave/blob/master/docs/DesignDocs/RemoteAttestationCollaterals.md), new API `oe_verify_evidence()` will supersede `oe_verify_report()`. So we 
only discuss scenario 2 here. But in both scenarios, the same function `oe_verify_quote_with_sgx_endorsements()`
is invoked for quote verificaiton.

The enclave-side and host-side plugin library implements in function `_verify_evidence()`, for SGX ECDSA-p256
quote verification, 3 functions are called in this function.
- `oe_get_sgx_endorsements()` and `oe_parse_sgx_endorsements()`
  - Get relevant endorsements, including SGX PCK cert CRL, TCB info, QE identity and etc
- `oe_verify_quote_with_sgx_endorsements()`
  - Verify quote with provided endorsements, including quote parsing, cert chain veriifcation, TCB level matching and etc
- `oe_sgx_extract_claims()`
  - Fill required and custom claims

## Background: Intel® SGX DCAP QVL library and API

For verification of SGX evidence in ECDSA format, the SGX DCAP QVL
library has the following relevant API functions defined in its
[header file](https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/QuoteVerification/dcap_quoteverify/inc/sgx_dcap_quoteverify.h):

```C
/**
 * Get supplemental data required size.
 * @param p_data_size[OUT] - Pointer to hold the size of the buffer in bytes required to contain all of the supplemental data.
 *
 * @return Status code of the operation, one of:
 *      - SGX_QL_SUCCESS
 *      - SGX_QL_ERROR_INVALID_PARAMETER
 *      - SGX_QL_ERROR_QVL_QVE_MISMATCH
 *      - SGX_QL_ENCLAVE_LOAD_ERROR
 **/
quote3_error_t sgx_qv_get_quote_supplemental_data_size(uint32_t *p_data_size)


/**
 * Perform quote verification.
 *
 * @param p_quote[IN] - Pointer to SGX Quote.
 * @param quote_size[IN] - Size of the buffer pointed to by p_quote (in bytes).
 * @param p_quote_collateral[IN] - This is a pointer to the Quote Certification Collateral provided by the caller.
 * @param expiration_check_date[IN] - This is the date that the QvE will use to determine if any of the inputted collateral have expired.
 * @param p_collateral_expiration_status[OUT] - Address of the outputted expiration status.  This input must not be NULL.
 * @param p_quote_verification_result[OUT] - Address of the outputted quote verification result.
 * @param p_qve_report_info[IN/OUT] - This parameter can be used in 2 ways.
 *        If p_qve_report_info is NOT NULL, the API will use Intel QvE to perform quote verification, and QvE will generate a report   using the target_info in sgx_ql_qe_report_info_t structure.
 *        if p_qve_report_info is NULL, the API will use QVL library to perform quote verification, not that the results can not be cryptographically authenticated in this mode.
 * @param supplemental_data_size[IN] - Size of the buffer pointed to by p_quote (in bytes).
 * @param p_supplemental_data[OUT] - The parameter is optional.  If it is NULL, supplemental_data_size must be 0.
 *
 * @return Status code of the operation, one of:
 *      - SGX_QL_SUCCESS
 *      - SGX_QL_ERROR_INVALID_PARAMETER
 *      - SGX_QL_QUOTE_FORMAT_UNSUPPORTED
 *      - SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED
 *      - SGX_QL_UNABLE_TO_GENERATE_REPORT
 *      - SGX_QL_ERROR_UNEXPECTED
 **/
quote3_error_t sgx_qv_verify_quote(
    const uint8_t *p_quote,
    uint32_t quote_size,
    const struct _sgx_ql_qve_collateral_t *p_quote_collateral,
    const time_t expiration_check_date,
    uint32_t *p_collateral_expiration_status,
    sgx_ql_qv_result_t *p_quote_verification_result,
    sgx_ql_qe_report_info_t *p_qve_report_info,
    uint32_t supplemental_data_size,
    uint8_t *p_supplemental_data)

```

Note that API `sgx_qv_verify_quote()` allows:
- Verifier controls quote verification via trusted QvE or untrusted QVL by specifing parameter `p_qve_report_info`
  - Intel SGX Quote Verification Enclave (QvE): Quote verification would be done inside QvE, and QvE would return a report which target for verifier's enclave, it means verifier can verify QvE's reutrn report and identity
  - Intel SGX Quote Verification Library (QVL): Quote verification would be done inside untrusted QVL library, verifier can use this way on a non-SGX capable system, but the result can not be cryptographically authenticated in this mode
- This API would return [supplemental data](https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/QuoteVerification/QvE/Include/sgx_qve_header.h) to allow verifier has an alternative verification policy
```C
/** Contains data that will allow an alternative quote verification policy. */
typedef struct _sgx_ql_qv_supplemental_t
{
    uint32_t version;                     ///< Supplemental data version
    time_t earliest_issue_date;           ///< Earliest issue date of all the collateral (UTC)
    time_t latest_issue_date;             ///< Latest issue date of all the collateral (UTC)
    time_t earliest_expiration_date;      ///< Earliest expiration date of all the collateral (UTC)
    time_t tcb_level_date_tag;            ///< The SGX TCB of the platform that generated the quote is not vulnerable
                                          ///< to any Security Advisory with an SGX TCB impact released on or before this date.
                                          ///< See Intel Security Center Advisories
    uint32_t pck_crl_num;                 ///< CRL Num from PCK Cert CRL
    uint32_t root_ca_crl_num;             ///< CRL Num from Root CA CRL
    uint32_t tcb_eval_ref_num;            ///< Lower number of the TCBInfo and QEIdentity
    uint8_t root_key_id[ROOT_KEY_ID_SIZE];///< ID of the collateral's root signer (hash of Root CA's public key SHA-384)
    sgx_key_128bit_t pck_ppid;            ///< PPID from remote platform.  Can be used for platform ownership checks
    sgx_cpu_svn_t tcb_cpusvn;             ///< CPUSVN of the remote platform's PCK Cert
    sgx_isv_svn_t tcb_pce_isvsvn;         ///< PCE_ISVNSVN of the remote platform's PCK Cert
    uint16_t pce_id;                      ///< PCE_ID of the remote platform
    uint8_t sgx_type;                     ///< Indicate the type of memory protection available on the platform, it should be one of Standard (0) and Scalable (1)

    // Multi-Package PCK cert related flags, they are only relevant to PCK Certificates issued by PCK Platform CA
    uint8_t platform_instance_id[PLATFORM_INSTANCE_ID_SIZE];///< Value of Platform Instance ID, 16 bytes
    pck_cert_flag_enum_t dynamic_platform;                  ///< Indicate whether a platform can be extended with additional packages - via Package Add calls to SGX Registration Backend
    pck_cert_flag_enum_t cached_keys;                   ///< Indicate whether platform root keys are cached by SGX Registration Backend
    pck_cert_flag_enum_t smt_enabled;                   ///< Indicate whether a plat form has SMT (simultaneous multithreading) enabled

} sgx_ql_qv_supplemental_t;
```


## Proposed Changes

### Options for retrieving SGX endorsements
There are two options for the OE SDK plugin library to retreive
SGX endorsments. 

#### Option 1: Keep existing implemention in SGX verifier plugin
In current plugin, if verifier doesn't provide SGX endoresements,
then it will call API `oe_get_sgx_endorsements()` to parse SGX ECDSA quote body
to get PCK cert chain first, then call OCALL API `oe_get_quote_verification_collateral_ocall`
to load Quote Provide Library(QPL) and connect to PCK Cert Caching Sever(PCCS) 
to get corresponding verification collaterals, including CRL, TCB and QE Identity and etc. 

#### Option 2: Ask DCAP QVL to retrieve endorsements
If verifier doesn't provide endorsments when calling DCAP QVL API, QVL API will
try parse quote body to get PCK cert chain, then load Quote Provide Library(QPL) 
and connect to PCK Cert Caching Sever(PCCS) to get corresponding verification
collaterals. 

#### Proposal: Ask DCAP QVL to retrieve endorsements
The proposal is to start by implementing option 2, the reasons are:
- Intel® SGX DCAP QVL library alreday has logic to parse quote, and get verfication collaterals
  Also the collateral definition may change sometimes, such as DCAP 1.7 release updated PCK cert
  extension field to add some items for multi-package platform
- If we keep using existing OE SDK implementaion, it means OE SDK need to update once Intel change
  verification collateral defintion

So with option 2, OE SDK don't need to maintain the complex SGX collateral retrieving & parsing logic,
also OE SDK don't care about SGX collateral change, because DCAP QVL will handle it. 


#### Link with the SGX DCAP QVL Library
In order to align with current implementaion of DCAP quote-ex, we will update
OE SDK host-side plugin library to dynamically detects the presence of QVL library 
and loads it at runtime. If the QVL library is present, it loads this library and 
calls into quote verificaton internal logic. Question: what if the library is missing?


### Add host-side verifier plugin library for OCALLs to support enclave-side SGX ECDSA-p256 quote verification
As quote verification will be done by DCAP QVL/QvE, for enclave-side plugin, we need to implement OCALLs\
in host-side verifier plugin library to invoke QvE.

In this proposal, we suggest to add one OCALL in `edl/sgx/attestation.edl` as below.
The OCALL is used for passing quote buffer and expiration time flag to host side.
All other relevant logic would be implemented in host side, file `host/sgx/ocalls.c`
and `host/sgx/quote.c`
 
Note that though only ECDSA-p256 quote is supported by now, the OCALL will keep `format_id`
and `opt_params` for forward compatibility.

```C
oe_result_t oe_verify_quote_ocall(
    [in] const oe_uuid_t* format_id,
    [in, size=opt_params_size] const void* opt_params,
    size_t opt_params_size,
    [in, size=quote_size] const void* p_quote,
    size_t quote_size,
    oe_datetime_t expiration_check_date,
    [out] uint32_t *p_collateral_expiration_status,
    [out] uint32_t *p_quote_verification_result,
    [in, out, size=qve_report_size] void* p_qve_report_info,
    size_t qve_report_size,
    [out, size=supplemental_data_size] void* p_supplemental_data,
    size_t supplemental_data_size,
    [out] size_t* p_supplemental_data_size_out);
```

#### Alternatives
Quote verification can be done in host side, only QvE Identity verification need to be 
done in enclave side, so we don't need above OCALL
- Finish quote verification in host side, verifier can only provide quote buffer, expiration
  check time and verifier enclave's target info
- Add another ECALL function, pass all the QvE returned results, then verify QvE report and 
  identity inside enclave, with new added `QvE report and identity verfication` API.

TODO: Need to investigate how to prevent quote into enclave in verifier's plugin

* For this alternative, do you mean that the quote will never be read into the application enclave?
That will require change in API model. So I think we can eliminate this alternative.*

### Update implementation of existing plugin API `oe_verify_evidence` and `oe_verify_quote_with_sgx_endorsements`

TODO: The proposal depends on above decision
  - If we can quote verification OCALL, then we just need to remove the logic about retrieving 
    endorsments, then call OCALL to verify quote. At last, call new added `QvE report and identity verfication` API
  - If all quote verification process done in host-side, then host side can choose to use
    trusted QvE vs untrusted QVL verification. For QvE verifcation, host-side need to ECALL to get
    target info first, then call all new added `QvE report and identity verfication` API

### Add function in enclave-side plugin for Intel® QvE Identity verification

After quote verification, verifier needs to verify Intel® QvE's idenity after quote verification
to make sure the results are from a trusted source.

Intel® SGX SDK provides a library named `sgx_dcap_tvl` to help verifier to verify QvE's identity,
[source file](https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/QuoteVerification/dcap_tvl/sgx_dcap_tvl.cpp)
This library uses hardcode QvE identity value, because:
- Get rid of x509 and JSON parser from verifier's TCB
- Most of QvE's identity would NOT change
The only identity info may change frequently is QvE's ISV SVN, so verifier to provide 
a SVN number as threshold, only when the current QvE's ISV SVN is larger or equal to the 
threshold, verifier can trust the QvE verification result.

As OE SDK cannot use Intel® SGX SDK trusted library directly, we need to port this library
into OE SDK.

```C
oe_result_t oe_verify_qve_report_and_identity(
        const uint8_t *p_quote,
        uint32_t quote_size,
        const sgx_ql_qe_report_info_t *p_qve_report_info,
        time_t expiration_check_date,
        uint32_t collateral_expiration_status,
        sgx_ql_qv_result_t quote_verification_result,
        const uint8_t *p_supplemental_data,
        uint32_t supplemental_data_size,
        sgx_isv_svn_t qve_isvsvn_threshold)
```
Note that all the QvE returned data are included in QvE report data to guarantee integrity. 
```C
QvE report_data = SHA256([nonce || quote || expiration_check_date || expiration_status || verification_result || supplemental_data] || 32 - 0x00)
```

Rough process of this API:
- Verify QvE report
- Verify report data, report_data = SHA256([nonce || quote || expiration_check_date || expiration_status || verification_result || supplemental_data] || 32 - 0x00)
- Check QvE Identity by comparing hardcode values and QvE report
  - Check Report.MRSIGNER == Hardcode QvE MRSIGNER
  - Check Misc Select, Attribute and ProdID are equal with hardcode values, Misc select and Attribute need to apply Mask before compare
  - Check Report.ISVSVN >= Hardcode ISVSVN
  
Note: this flow can be implemented in the enclave-side '_verify_evidence()` and _verify_report()` functions.

### Extend `claims` definition for more supplemental data
TODO

### Add more error code in `oe_result_t` to indicate specific quote verification error
TODO

### Remove repetitive quote verification code in existing enclave-side SGX verifier plugin
#### In enclave-side verifier plugin file `common/sgx/quote.c`, only keep 2 existing APIs, remove all other APIs in this file

- `oe_verify_quote_with_sgx_endorsements()`
  - Updated implementation 
- `oe_verify_sgx_quote()`
  - Keep backward compatibility

TODO: Need to evaluate whehter we can remove other logics about cert/CRL/JSON operations, 
such as `oe_cert_chain_read_pem` in `enclave/crypto/cert.c`

#### Remove SGX endorsment logic in file `common/sgx/endorsements.c`
TODO: Need to evaluate whether we can remove logic related to `oe_get_quote_verification_collateral_ocall`,
as we can utilize DCAP QVL to get corresponding endorsments.

# Authors

- Hongyan Jiang (@hyjiang)
