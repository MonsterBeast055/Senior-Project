# Test suite.
#
# A disassembler is correctness-critical: a wrong branch target silently
# produces a plausible, wrong CFG, and every downstream consumer - the UI and
# the model - inherits the error without any signal that it happened. Tests are
# how that gets caught.
#
# Deliberately dependency-free (assert-based) so nothing needs installing to run
# them. Swap in Catch2 or GoogleTest later if the suite outgrows it.

add_executable(sp_tests
    "test_main.cpp"
    "test_address_space.cpp"
    "test_provenance.cpp"
    "test_code_map.cpp"
    "test_instruction_storage.cpp"
    "test_cfg.cpp"
    "test_pe_format.cpp"
    "test_cfg_builder.cpp"
    "test_json_exporter.cpp"
    "test_call_graph.cpp"
    "test_strings.cpp"
    "test_reachability.cpp"
)

target_link_libraries(sp_tests PRIVATE sp_engine)
target_compile_features(sp_tests PRIVATE cxx_std_20)

add_test(NAME sp_tests COMMAND sp_tests)
