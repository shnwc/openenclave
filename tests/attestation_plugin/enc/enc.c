// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/attestation/sgx/attester.h>
#include <openenclave/attestation/sgx/verifier.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgx/plugin.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/trace.h>
#include <stdio.h>
#include <string.h>

#include "../../../common/sgx/quote.h"
#include "../plugin/tests.h"
#include "plugin_t.h"

static oe_uuid_t sgx_ecdsa_uuid = {OE_SGX_ECDSA_P256_PLUGIN_UUID};
static oe_uuid_t sgx_local_uuid = {OE_SGX_LOCAL_ATTESTATION_PLUGIN_UUID};

void run_runtime_test()
{
    test_runtime();
}

void register_sgx()
{
    printf("====== running register_sgx\n");

    OE_TEST_CODE(oe_initialize_attester_plugins(), OE_OK);
    register_verifier();
}

void unregister_sgx()
{
    printf("====== running unregister_sgx\n");

    OE_TEST_CODE(oe_shutdown_attester_plugins(), OE_OK);
    unregister_verifier();
}

static void _test_sgx_remote()
{
    printf("====== running _test_sgx_remote\n");
    uint8_t* evidence = NULL;
    size_t evidence_size = 0;
    uint8_t* endorsements = NULL;
    size_t endorsements_size = 0;

    // Get a remote attestation report.
    printf("====== running _test_sgx_remote #1: Just evidence\n");
    OE_TEST_CODE(
        oe_get_evidence(
            &sgx_ecdsa_uuid,
            0,
            NULL,
            0,
            NULL,
            0,
            &evidence,
            &evidence_size,
            NULL,
            0),
        OE_OK);

    printf("    ====== evidence_size=%d\n", evidence_size);

    verify_sgx_evidence(evidence, evidence_size, NULL, 0, NULL, 0, false);

    OE_TEST(oe_free_evidence(evidence) == OE_OK);

    // Get a remote report with endorsements.
    printf("====== running _test_sgx_remote #2: + Endorsements\n");
    OE_TEST_CODE(
        oe_get_evidence(
            &sgx_ecdsa_uuid,
            0,
            NULL,
            0,
            NULL,
            0,
            &evidence,
            &evidence_size,
            &endorsements,
            &endorsements_size),
        OE_OK);

    printf(
        "    ====== evidence_size=%d endorsements_size=%d\n",
        evidence_size,
        endorsements_size);

    verify_sgx_evidence(
        evidence,
        evidence_size,
        endorsements,
        endorsements_size,
        NULL,
        0,
        false);

    OE_TEST(oe_free_evidence(evidence) == OE_OK);
    OE_TEST(oe_free_endorsements(endorsements) == OE_OK);

    // Get a remote report with both.
    printf("====== running _test_sgx_remote #3: + Claims\n");
    OE_TEST_CODE(
        oe_get_evidence(
            &sgx_ecdsa_uuid,
            0,
            test_claims,
            NUM_TEST_CLAIMS,
            NULL,
            0,
            &evidence,
            &evidence_size,
            &endorsements,
            &endorsements_size),
        OE_OK);

    printf(
        "    ====== evidence_size=%d endorsements_size=%d claims_length=%d\n",
        evidence_size,
        endorsements_size,
        NUM_TEST_CLAIMS);

    verify_sgx_evidence(
        evidence,
        evidence_size,
        endorsements,
        endorsements_size,
        test_claims,
        NUM_TEST_CLAIMS,
        false);

    OE_TEST(
        host_verify(evidence, evidence_size, endorsements, endorsements_size) ==
        OE_OK);

    OE_TEST(oe_free_evidence(evidence) == OE_OK);
    OE_TEST(oe_free_endorsements(endorsements) == OE_OK);
}

static void _test_sgx_local()
{
    uint8_t* report = NULL;
    size_t report_size = 0;
    void* target = NULL;
    size_t target_size = 0;
    uint8_t* evidence = NULL;
    size_t evidence_size = 0;

    printf("====== running _test_sgx_local\n");
    printf("====== running _test_sgx_local #0: Getting target info.\n");
    OE_TEST(oe_get_report(0, NULL, 0, NULL, 0, &report, &report_size) == OE_OK);

    OE_TEST(
        oe_get_target_info(report, report_size, &target, &target_size) ==
        OE_OK);

    oe_free_report(report);

    // Only evidence.
    printf("====== running _test_sgx_local #1: Just evidence\n");
    OE_TEST(
        oe_get_evidence(
            &sgx_local_uuid,
            0,
            NULL,
            0,
            target,
            target_size,
            &evidence,
            &evidence_size,
            NULL,
            0) == OE_OK);

    verify_sgx_evidence(evidence, evidence_size, NULL, 0, NULL, 0, true);

    OE_TEST(oe_free_evidence(evidence) == OE_OK);

    // Evidence + claims.
    printf("====== running _test_sgx_local #2: + Claims\n");
    OE_TEST(
        oe_get_evidence(
            &sgx_local_uuid,
            0,
            test_claims,
            NUM_TEST_CLAIMS,
            target,
            target_size,
            &evidence,
            &evidence_size,
            NULL,
            0) == OE_OK);

    verify_sgx_evidence(
        evidence, evidence_size, NULL, 0, test_claims, NUM_TEST_CLAIMS, true);

    OE_TEST(oe_free_evidence(evidence) == OE_OK);
    oe_free_target_info(target);
}

void test_sgx()
{
    printf("====== running test_sgx\n");

    _test_sgx_remote();
    _test_sgx_local();
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    128,  /* HeapPageCount */
    128,  /* StackPageCount */
    1);   /* TCSCount */
