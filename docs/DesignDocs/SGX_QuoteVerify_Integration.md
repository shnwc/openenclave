Attestation: OE SDK Integration with Intel® SGX DCAP Quote Verification Library for SGX Evidence Verification
====

This design document proposes an update of the OE SDK implementation
for integration with the Intel® SGX Data Center Attestation Primitives (DCAP)
Quote Verification Library (QVL), for support of evidence verification in
ECDSA-p256 format.

# Motivation

Existing OE SDK implements the functionality for SGX ECDSA quote verification.
As implemented in code file `common/sgx/quote.c`, the verification code
performs SGX cert chain verification and Enclave Identity
verification, including x509 parser, cert revocation checking, JSON parser and
etc. Also it uses some 3rd-party libraries, such as mbedtls.

However, there are a few areas that could be improved:
- Current SGX ECDSA quote verification logic in `common/sgx/quote.c`
  is not a complete implementation, e.g.
  - Only check quote version number in function `_validate_sgx_quote()`
    in file `common/sgx/quote.c`
  - Only allow TCB level `UpToDate`, all other TCB levels would be treated
    as invalid. But in SGX design, some other TCB levels such as `OutOfDate`,
    `SWConfigNeeded` should not be treated as critical error, it's up to
    a verifier application to decide whehter the platform TCB is valid or not
    for its intended usages.
- In current implementaion, all the quote verification logic is
  built into verifier enclaves. This means that OE SDK greatly increases the TCB of
  verifier enclaves. If security bugs in verification logic,
  including 3rd-party component, are discovered, verifier enclaves need to be
  upgraded and rebuilt.

# User Experience

The proposed update only changes the internal implementation of the OE SDK
attestation software stack. It does not impact the
[OE SDK attestation API](https://github.com/openenclave/openenclave/blob/master/docs/DesignDocs/Attestation_API_Proposal.md).

With the integration of Intel® SGX DCAP QVL (including an untrusted library
(called QVL when there is no ambiguity)
and a Quote Verification Enclave (QvE)), a verifier's call to OE SDK API
`oe_verify_evidence()` for verification of SGX ECDSA evidence would trigger
quote verification by invoking QVL or QvE, depending on whether the call is
from the enclave side or the host side.

Integration of the DCAP QVL depends on the installation of
Intel® SGX DCAP packages `libsgx-dcap-quote-verify` and `libsgx-ae-qve` and
their dependencies, as well as proper configuration of the components and their
access to dependent backend services (e.g. Quote Provider Library and
Provisioning Certificate Cashing Service (PCCS)). Details for the DCAP quote
verification library installation and configuration are outside the scope of
this document.

# Specification

## Existing OE SDK Implementation

### Implementation of the SGX ECDSA-p256 verifier plugin

The OE SDK framework implementation searchs for a verifier plugin that
supports the requested evidence format, and invoke the `verify_evidence()` or
`verify_report()` entry point of the selected plugin.

The SGX ECDSA-p256 verifier plugin is implemented in code files
`enclave/sgx/report.c`, `common/sgx/verifier.c` and
`common/sgx/quote.c`. The same source tree implements both the enclave-side and
host-side verifier plugins.

There are 2 different verifier application / enclave scenarios in current
implementation for SGX ECDSA quote verification:
- Scenario 1 - Call `oe_verify_report()` to verify SGX remote report (aka SGX quote)
- Scenario 2 - Call `oe_verify_evidence()` to verify evidence in format
  `OE_FORMAT_UUID_SGX_ECDSA_P256`.

Based on design doc [Remote Attestation Collaterals](https://github.com/openenclave/openenclave/blob/master/docs/DesignDocs/RemoteAttestationCollaterals.md),
new API `oe_verify_evidence()` will supersede
`oe_verify_report()`. So we only discuss scenario 2 here. But in both scenarios,
the same function `oe_verify_quote_with_sgx_endorsements()` is invoked for
quote verification.

For SGX ECDSA-p256 quote verification, in the enclave-side and host-side plugin
implementation of function `_verify_evidence()` in `common/sgx/verifier.c`,
several functions are called.
- `oe_get_sgx_endorsements()` and `oe_parse_sgx_endorsements()`
  - Get relevant endorsements, including SGX PCK cert CRL, TCB info, QE identity
    and etc
- `oe_verify_quote_with_sgx_endorsements()`
  - Verify quote with provided endorsements, including quote parsing, cert chain
    veriifcation, TCB level matching and etc
- `oe_sgx_extract_claims()`
  - Fill required and custom claims

## Background: Intel® SGX DCAP QVL library and API

For verification of SGX ECDSA quotes, the SGX DCAP QVL
library has the following relevant API functions defined in its
[header file](https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/QuoteVerification/dcap_quoteverify/inc/sgx_dcap_quoteverify.h):

```C
/**
 * Get supplemental data required size.
 * @param p_data_size[OUT] - Pointer to hold the size of the buffer in bytes
 *  required to contain all of the supplemental data.
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
 * @param p_quote_collateral[IN] - This is a pointer to the Quote Certification
 *        Collateral provided by the caller.
 * @param expiration_check_date[IN] - This is the date that the QvE will use to
 *        determine if any of the inputted collateral have expired.
 * @param p_collateral_expiration_status[OUT] - Address of the output expiration
 *        status.  This input must not be NULL.
 * @param p_quote_verification_result[OUT] - Address of the output quote
 *  verification result.
 * @param p_qve_report_info[IN/OUT] - This parameter can be used in 2 ways.
 *        If p_qve_report_info is NOT NULL, the API will use Intel QvE to
 *        perform quote verification, and QvE will generate a report   using the
 *        target_info in sgx_ql_qe_report_info_t structure.
 *        if p_qve_report_info is NULL, the API will use QVL library to perform
 *        quote verification, not that the results can not be cryptographically
 *        authenticated in this mode.
 * @param supplemental_data_size[IN] - Size of the buffer pointed to by p_quote (in bytes).
 * @param p_supplemental_data[OUT] - The parameter is optional.  If it is NULL,
 *        supplemental_data_size must be 0.
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

Notes on the API function `sgx_qv_verify_quote()`:
- Verifier application (called the verifier) controls quote verification via trusted
  QvE or untrusted QVL by specifing parameter `p_qve_report_info`
  - Trusted QvE when this parameter is non-NULL, containing the `target_info`
    for the verifier enclave that verifies the QvE security properties:
    Quote verification would be done inside QvE, and QvE would return a report
    targeting the verifier enclave, it means the verifier can verify QvE's
    reutrn report and identity
  - Untrusted QVL when this parameter is NULL:
    Quote verification would be done inside untrusted QVL library, the verifier can
    use this way on a non-SGX capable system, but the result can not be
    cryptographically authenticated in this mode
- This API can return a [supplemental data structure](https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/QuoteVerification/QvE/Include/sgx_qve_header.h)
to allow theverifier to have an alternative verification policy

```C
/** Contains data that will allow an alternative quote verification policy. */
typedef struct _sgx_ql_qv_supplemental_t
{
    uint32_t version;               ///< Supplemental data version
    time_t earliest_issue_date;     ///< Earliest issue date of all the collateral (UTC)
    time_t latest_issue_date;       ///< Latest issue date of all the collateral (UTC)
    time_t earliest_expiration_date;///< Earliest expiration date of all the collateral (UTC)
    time_t tcb_level_date_tag;      ///< The SGX TCB of the platform that generated the quote is not vulnerable
                                    ///< to any Security Advisory with an SGX TCB impact released on or before this date
                                    ///< See [Intel Security Center Advisories](https://www.intel.com/content/www/us/en/security-center/default.html)
    uint32_t pck_crl_num;           ///< CRL Num from PCK Cert CRL
    uint32_t root_ca_crl_num;       ///< CRL Num from Root CA CRL
    uint32_t tcb_eval_ref_num;      ///< Lower number of the TCBInfo and QEIdentity
    uint8_t root_key_id[48];        ///< ID of the collateral's root signer (hash of Root CA's public key SHA-384)
    sgx_key_128bit_t pck_ppid;      ///< PPID from remote platform.  Can be used for platform ownership checks
    sgx_cpu_svn_t tcb_cpusvn;       ///< CPUSVN of the remote platform's PCK Cert
    sgx_isv_svn_t tcb_pce_isvsvn;   ///< PCE_ISVNSVN of the remote platform's PCK Cert
    uint16_t pce_id;                ///< PCE_ID of the remote platform
    uint8_t sgx_type;               ///< Indicate the type of memory protection available on the platform, it should be
                                    ///< one of Standard (0) and Scalable (1)

    // Multi-Package PCK cert related flags, they are only relevant to PCK Certificates issued by PCK Platform CA
    uint8_t platform_instance_id[16];///< Value of Platform Instance ID, 16 bytes
    pck_cert_flag_enum_t dynamic_platform; ///< Indicate whether a platform can be extended with additional packages
                                           ///< via Package Add calls to SGX Registration Backend
    pck_cert_flag_enum_t cached_keys;      ///< Indicate whether platform root keys are cached by SGX Registration Backend
    pck_cert_flag_enum_t smt_enabled;      ///< Indicate whether a plat form has SMT (simultaneous multithreading) enabled

} sgx_ql_qv_supplemental_t;
```

Question: so QVL does not have an API similar to `oe_get_sgx_endorsements()` in OE SDK?

## Proposed Changes

### Options for retrieving SGX endorsements
There are two options for the OE SDK plugin library to retreive SGX endorsments.

#### Option 1: Keep existing implemention in SGX verifier plugin
In the current plugin implementation, if the verifier doesn't provide SGX endoresements, it
calls API `oe_get_sgx_endorsements()` to parse SGX ECDSA quote body to get PCK
cert chain first, then calls OCALL API `oe_get_quote_verification_collateral_ocall()`
to load Quote Provide Library(QPL) and connect to PCK Cert Caching Sever(PCCS)
to get corresponding verification collaterals, including CRL, TCB and QE
Identity and etc.

#### Option 2: Ask DCAP QVL to retrieve endorsements
If the verifier doesn't provide endorsments when calling DCAP QVL API, the QVL API
implementation will parse quote body to get PCK cert chain, then load QPL
and connect to PCCS to get corresponding verification
collaterals.

#### Proposal: Ask DCAP QVL to retrieve endorsements
The proposal is to implement option 2, the reasons are:
- The Intel SGX DCAP QVL already has logic to parse quote, and gets
  verification collaterals
- The collateral definition may change from time to time, e.g. DCAP 1.7 release
  updated PCK cert extension to add new fields for support of multi-package
  platforms
- If we stay with the existing OE SDK implementaion
  - The implementation would need to be updated whenver the verification
    collateral defintion is changed
  - The OE SDK logic for retrieving and parsing endorsements increases
    verifier enclave TCB.

With option 2, OE SDK doesn't need to maintain the complex logic for SGX collateral
retrieving & parsing, nor need to be updated in response to changes
in SGX collateral definition.

### Link with the SGX DCAP QVL Library
To align with the current implementaion of SGX quote-ex library integration,
the OE SDK host-side plugin library will dynamically detect the presence of QVL
library and loads it at runtime. In case the QVL library can't be found,
an error will be returned.

### Add OCALLs to host-side verifier plugin library to support enclave-side SGX ECDSA-p256 quote verification
As quote verification will be done by DCAP QVL/QvE, for enclave-side plugin,
OCALLs in host-side verifier plugin library will be to invoke QVL/QvE.

In this proposal, we will add one OCALL `oe_verify_quote_ocall()` in
`edl/sgx/attestation.edl`.
The OCALL is used for passing quote buffer and expiration time flag to host side.
All other relevant logic will be implemented on the host side, in files
`host/sgx/ocalls.c` and `host/sgx/quote.c`.

Note that currently only ECDSA-p256 quotes are supported, but the OCALL will keep
`format_id` and `opt_params` for forward compatibility.

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

### Update implementation of existing plugin functions

These plugin functions include `_verify_evidence()`, `_verify_report()`
and `oe_verify_quote_with_sgx_endorsements()`.

- Update API `oe_verify_quote_with_sgx_endorsements()` implementation as below:
  - Input parameter doesn't change.
  - In host-side plugin:
    - Set input parameter `p_qve_report_info` to NULL, then call host-side
      function `oe_sgx_verify_quote()`, which will call SGX QVL library to
      verify quote.
  - In enclave-side plugin:
    - Construct structure `sgx_ql_qe_report_info_t` as below, `nonce` and
      `app_enclave_target_info` are input, qve_report is QvE report which
      target to application enclave.
    ```C
    typedef struct _sgx_ql_qe_report_info_t {
      sgx_quote_nonce_t nonce;
      sgx_target_info_t app_enclave_target_info;
      sgx_report_t qve_report;
    }sgx_ql_qe_report_info_t;
    ```
    - Call OCALL function `oe_verify_quote_ocall()` to host-side plugin library
      to verify SGX quote.
    - With all the QvE return values, call new API.
      `oe_verify_qve_report_and_identity()` (described below) to
      verify QvE report and identity.
- In API `_verify_evidence()`, remove function call `oe_get_sgx_endorsements()`,
  and only call `oe_parse_sgx_endorsements()` if caller provides an endorsement buffer
- In API `_verify_report()` and relevant internal APIs, such as
  `oe_verify_report_internal()` and `oe_verify_sgx_quote()`, remove the code that
  loads QPL and retrieves endorsements.

### Add function in enclave-side plugin for QvE Identity verification

For enclave-side verifier plugin, after quote verification, it needs to verify that the result
comes from a trusted QvE.

Intel® SGX SDK provides a library named `sgx_dcap_tvl` to help the verifier to
verify QvE's identity, you can refer to [source file](https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/QuoteVerification/dcap_tvl/sgx_dcap_tvl.cpp)

This library uses hardcoded QvE identity values, because:
- There is no need for x509 and JSON parser in verifier enclave's TCB.
- Most of QvE's identity attributes only change infrequently.

The only identity info may change more often is QvE's ISV SVN, so the verifier needs
to provide a SVN number as threshold, only when current QvE's ISV SVN is equal to
or larger than this threshold, the verifier can trust the QvE verification result.
The verifier can get latest QvE ISV SVN from [QvE Identity at Intel® Provisioning
Cert Server](https://api.portal.trustedservices.intel.com/documentation#pcs-qve-identity-v2)

As OE SDK cannot use Intel® SGX SDK trusted library directly, we need to port
this library into OE SDK as part of enclave-side plugin.

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
All the data returned by the QvE are included in the QvE report data field for
integrity protection.
```C
QvE report_data = SHA256([nonce || quote || expiration_check_date ||
expiration_status || verification_result || supplemental_data] || 32 - 0x00)
```

The flow of the API function `oe_verify_qve_report_and_identity()` is as below:
- Verify QvE report.
- Verify report data (report data described as above).
- Check QvE Identity by comparing QvE report fields against hardcode values.
  - Check that Report.MRSIGNER equals to Hardcoded QvE MRSIGNER.
  - Check that Misc Select, Attribute and ProdID equal to the hardcoded values,
    Misc select and Attribute need to apply Mask before comparison.
- Check that Report.ISVSVN >= Hardcoded ISV SVN.

Options to provide QvE ISV SVN threshold:
- Option 1: Hardcode QvE ISV SVN in enclave-side plugin. Everytime QvE
            ISV SVN is updated, the plugin library implementation will need to
            be updated to stay in sync.
- Option 2: Update existing enclave-side plugin API to allow the verifier to input
            QvE ISV SVN threshold value. But it requires plugin API change, also
            it's NOT TEE agnostic.

We propose option 1 to avoid plugin API change.

### Update claims list to add SGX Quote Verification status and QVL/QvE returned supplemental data
In SGX remote attestation, the verifier may want to provide a different quote
verification policy than the one enforced by the sgx_qv_verify_quote() API.

The proposal is to extend known claims definition with new SGX related
claims.

SGX quote verification API `sgx_qv_verify_quote()` returns 2 types of errors,
fatal errors or non-fatal errors:
- Fatal error: such as cert chain verification failed, cert revoked, API will
  return corresponding error code directly
- Non-fatal error, such as cert chain out-of-date, API will return success, but
  there is an output parameter to indicate the specific error code. In this case,
  the verifier can decide whehter the SGX quote is valid based on their own policy.

So we propose to introduce a new SGX claim `SGX Quote Verification status` to
indicate QVL/QvE return status. The verifier can check the status to see if there
is a non-fatal error during quote verification.

- SGX Quote Verification status - Indicate the quote verification result, it
  would have 3 types
  - OE_OK - Quote verification passed, and TCB level is up to date
  - Fatal error - Quote verification failed with fatal error, such as signature
    is invalid
  - Non-Fatal error - API return OE_OK, but `SGX platform status` in claims
    return corresponding error. The verifier can refer to this status in his/her
    verification policy. Non-Fatal error should be one of below:

```C
   OE_SGX_CONFIG_NEEDED // Quote verification passed and the platform is patched
                        // to latest TCB level, but additional configuration of
                        // the SGX platform may be neede. For example, attester
                        // may need to enable/disable SMT in BIOS
   OE_SGX_OUT_OF_DATE  // The Quote is good but TCB level of the platform is
                       // out of date, additional configuration of the SGX
                       // Platform at its current patching level may be needed.
                       // The platform needs patching to be at the latest TCB level
   OE_SGX_SW_HARDENING_NEEDED  // The TCB level of the platform is up to date,
                               // but SGX SW Hardening is needed. For example,
                               // attester may need to apply LVI mitgation in
                               // his/her enclave by linking LIV version SDK
   OE_SGX_CONFIG_AND_SW_HARDENING_NEEDED  // The TCB level of the platform is up
                                          // to date, but additional
                                          // configuration of the platform at
                                          // its current patching level may be
                                          // needed. Moreove, SGX SW Hardening
                                          // is also needed. For example,
                                          // attester may need enable/disable
                                          // SMT in BIOS, also he/she needs to
                                          // apply LVI mitgation in enclave

Note that SGX TCB = Platform CPU SVN + SGX SW PCE SVN
```
In addition, if the verifier needs to provide a different quote verification policy
beyond the policy enforced by the sgx_qv_verify_quote() API, the verifier can
request sgx_qv_verify_quote() API to return supplemental data. The detailed
supplemental data definition are described in above `Background` section.

So we also propose to add SGX supplemental data into claims.

[PR 3353](https://github.com/openenclave/openenclave/pull/3353) added SGX
endorsements into SGX-specific claims, here we propose to use SGX supplemental
data (returned by QVL/QvE) instead. Because user needs to parse the endorsements
by himself if we only return the endorsements directly, but parsing x509 cert
chain/CRL and JSON is quite a complex task.

The new SGX-Specific claims definition (Pls refer to `Background` section for
the descripton of each SGX specific claim):

```C
#define OE_CLAIM_SGX_QUOTE_VERIFY_STATUS "sgx_quote_verify_status"

#define OE_CLAIM_SGX_TCB_LEVEL_DATE_TAG "sgx_tcb_level_date_tag"
#define OE_CLAIM_SGX_PCK_CRL_NUM "sgx_pck_crl_num"
#define OE_CLAIM_SGX_ROOT_CA_CRL_NUM "sgx_root_ca_crl_num"
#define OE_CLAIM_SGX_TCB_EVAL_REF_NUM "sgx_tcb_eval_ref_num"
#define OE_CLAIM_SGX_ROOT_KEY_ID "sgx_root_key_id"
#define OE_CLAIM_SGX_PCK_PPID "sgx_pck_ppid"
#define OE_CLAIM_SGX_TCB_CPUSVN "sgx_tcb_cpusvn"
#define OE_CLAIM_SGX_TCB_PCE_ISVSVN "sgx_tcb_pce_isvsvn"
#define OE_CLAIM_SGX_PCE_ID "sgx_pce_id"
#define OE_CLAIM_SGX_TYPE "sgx_type"
#define OE_CLAIM_SGX_PLATFORM_INSTANCE_ID "sgx_platform_instance_id"
#define OE_CLAIM_SGX_DYNAMIC_PLATFORM "sgx_dynamic_platform"
#define OE_CLAIM_SGX_CACHED_KEYS "sgx_cached_keys"
#define OE_CLAIM_SGX_SMT_ENABLED "sgx_smt_enabled"

#define OE_SGX_CLAIMS_COUNT 15
```

### Update `oe_sgx_extract_claims()` to remove SGX endorsement dependency
As SGX endrosments will be retrieved from SGX DCAP QVL library, so we will try
to get QVL/QvE returned supplemental data first, then use the returned info to
replace current endorsement to fill claims.

### Remove no-longer-used quote verification code in existing enclave-side SGX verifier plugin
#### In verifier plugin file `common/sgx/quote.c`, only keep 2 existing APIs, remove all other APIs in this file

- `oe_verify_quote_with_sgx_endorsements()`
  - Updated implementation
- `oe_verify_sgx_quote()`
  - Keep backward compatibility

#### Remove other utility functions
- `common/sgx/collateral.h & .c`
- `common/sgx/endosements.h & .c`, only keep `oe_parse_sgx_endorsements()` as
  user may provide endorsements
- `common/sgx/qeidentity.h & .c`
- `common/sgx/sgxcertextension.c`
- `common/sgx/tcbinfo.h & .c`
- `common/sgx/tlsverifier.c`

#### Clean header files to remove some no-longer-used interal APIs and macros


# Authors

- Hongyan Jiang (@hyjiang)
- Shanwei Cen (@shnwc)
