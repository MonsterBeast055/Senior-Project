#include "test_harness.h"

#include <cstdio>

void test_address_space();
void test_provenance();
void test_code_map();
void test_instruction_storage();
void test_cfg();
void test_pe_format();
void test_cfg_builder();
void test_json_exporter();
void test_call_graph();
void test_strings();
void test_api_classifier();
void test_reachability();
void test_pe_hardener();

int main()
{
    test_address_space();
    test_provenance();
    test_code_map();
    test_instruction_storage();
    test_cfg();
    test_pe_format();
    test_cfg_builder();
    test_json_exporter();
    test_call_graph();
    test_strings();
    test_api_classifier();
    test_reachability();
    test_pe_hardener();

    const auto& failures = sp::test::failures();
    if (failures.empty()) {
        std::printf("\nall tests passed\n");
        return 0;
    }

    std::printf("\n%zu failure(s)\n", failures.size());
    return 1;
}
