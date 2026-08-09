#include "test_harness.h"

#include "sp/analysis/ApiClassifier.h"
#include "sp/analysis/Reachability.h"

#include <map>
#include <string>

using namespace sp;
using namespace sp::analysis;

namespace {

Function make_function(core::VA entry, std::vector<std::string> apis,
                       std::vector<core::VA> callees = {})
{
    Function f;
    f.entry = entry;
    f.api_calls = std::move(apis);
    f.callees = std::move(callees);
    return f;
}

} // namespace

void test_api_classifier()
{
    SP_TEST("api classifier: name normalisation");
    {
        SP_CHECK(ApiClassifier::bare_name(
            "api-ms-win-core-registry-l1-1-0.dll!RegCreateKeyExW") == "RegCreateKeyExW");
        SP_CHECK(ApiClassifier::bare_name("KERNEL32.dll!CreateFileW") == "CreateFileW");
        SP_CHECK(ApiClassifier::bare_name("CreateFileW") == "CreateFileW");

        SP_CHECK(ApiClassifier::library_of("KERNEL32.dll!CreateFileW") == "KERNEL32.dll");
        SP_CHECK(ApiClassifier::library_of("CreateFileW").empty());
    }

    SP_TEST("api classifier: category from api-set name");
    {
        // The API-set name encodes the functional area, so a category comes free.
        SP_CHECK_EQ(ApiClassifier::categorize(
            "api-ms-win-core-registry-l1-1-0.dll!RegCloseKey"), ApiCategory::Registry);
        SP_CHECK_EQ(ApiClassifier::categorize(
            "api-ms-win-core-file-l1-1-0.dll!ReadFile"), ApiCategory::File);
        SP_CHECK_EQ(ApiClassifier::categorize(
            "api-ms-win-core-synch-l1-1-0.dll!SetEvent"),
            ApiCategory::Synchronization);
        SP_CHECK_EQ(ApiClassifier::categorize(
            "api-ms-win-core-com-l1-1-0.dll!CoCreateInstance"), ApiCategory::Com);
    }

    SP_TEST("api classifier: category from classic dll names");
    {
        SP_CHECK_EQ(ApiClassifier::categorize("USER32.dll!MessageBoxW"), ApiCategory::Ui);
        SP_CHECK_EQ(ApiClassifier::categorize("WS2_32.dll!recv"), ApiCategory::Network);
        SP_CHECK_EQ(ApiClassifier::categorize("ADVAPI32.dll!RegOpenKeyExW"),
                    ApiCategory::Registry);
        SP_CHECK_EQ(ApiClassifier::categorize("something.dll!Whatever"),
                    ApiCategory::Unknown);
    }

    SP_TEST("api classifier: input sources");
    {
        SP_CHECK_EQ(ApiClassifier::input_source_of("WS2_32.dll!recv"),
                    InputSource::Network);
        SP_CHECK_EQ(ApiClassifier::input_source_of(
            "api-ms-win-core-file-l1-1-0.dll!ReadFile"), InputSource::File);

        // A/W suffixes are the same API.
        SP_CHECK_EQ(ApiClassifier::input_source_of("KERNEL32.dll!GetCommandLineW"),
                    InputSource::CommandLine);
        SP_CHECK_EQ(ApiClassifier::input_source_of("ADVAPI32.dll!RegQueryValueExW"),
                    InputSource::Registry);

        SP_CHECK_EQ(ApiClassifier::input_source_of("KERNEL32.dll!CloseHandle"),
                    InputSource::None);
    }

    SP_TEST("api classifier: risky sinks");
    {
        SP_CHECK_EQ(ApiClassifier::sink_of("msvcrt.dll!strcpy"),
                    SinkKind::UnboundedCopy);
        SP_CHECK_EQ(ApiClassifier::sink_of("msvcrt.dll!memcpy"),
                    SinkKind::BoundedCopy);
        SP_CHECK_EQ(ApiClassifier::sink_of("KERNEL32.dll!CreateProcessW"),
                    SinkKind::ProcessLaunch);
        SP_CHECK_EQ(ApiClassifier::sink_of("KERNEL32.dll!WriteProcessMemory"),
                    SinkKind::RemoteWrite);
        SP_CHECK_EQ(ApiClassifier::sink_of("KERNEL32.dll!CloseHandle"), SinkKind::None);
    }

    SP_TEST("api classifier: the _s safe variants must not match");
    {
        // strcpy_s is the bounds-checked replacement. Flagging it would be a
        // false positive on code that did the right thing - the worst kind.
        SP_CHECK_EQ(ApiClassifier::sink_of("msvcrt.dll!strcpy_s"), SinkKind::None);
        SP_CHECK_EQ(ApiClassifier::sink_of("msvcrt.dll!memcpy_s"), SinkKind::None);
        SP_CHECK_EQ(ApiClassifier::sink_of("msvcrt.dll!sprintf_s"), SinkKind::None);

        // CRT decoration should still resolve to the unsafe original.
        SP_CHECK_EQ(ApiClassifier::sink_of(
            "api-ms-win-crt-private-l1-1-0.dll!_o_strcpy"), SinkKind::UnboundedCopy);
    }

    SP_TEST("api classifier: severity ordering is sane");
    {
        // An unbounded copy has no safe calling convention at all, so it
        // outranks operations that are only dangerous with bad input.
        SP_CHECK(base_severity(SinkKind::UnboundedCopy)
                 > base_severity(SinkKind::BoundedCopy));
        SP_CHECK(base_severity(SinkKind::UnboundedCopy) == SinkSeverity::High);
        SP_CHECK(base_severity(SinkKind::FileWrite) == SinkSeverity::Informational);
    }

    SP_TEST("api classifier: notable behaviours");
    {
        SP_CHECK(ApiClassifier::is_notable_behavior("KERNEL32.dll!CreateRemoteThread"));
        SP_CHECK(ApiClassifier::is_notable_behavior("KERNEL32.dll!IsDebuggerPresent"));
        SP_CHECK(ApiClassifier::is_notable_behavior("ADVAPI32.dll!RegSetValueExW"));
        SP_CHECK(!ApiClassifier::is_notable_behavior("KERNEL32.dll!CloseHandle"));
    }
}

void test_reachability()
{
    ReachabilityOptions options;

    SP_TEST("reachability: sink reachable from an input source");
    {
        // main -> parse -> copy, where main reads the command line and copy
        // calls strcpy. This is the shape that makes a finding impactful.
        std::map<core::VA, Function> functions;
        functions[0x1000] = make_function(0x1000, { "KERNEL32.dll!GetCommandLineW" },
                                          { 0x2000 });
        functions[0x2000] = make_function(0x2000, {}, { 0x3000 });
        functions[0x3000] = make_function(0x3000, { "msvcrt.dll!strcpy" });

        CallGraph graph;
        graph.build(functions);

        Reachability reach;
        reach.analyze(functions, graph, options);

        SP_CHECK_EQ(reach.sources().size(), std::size_t{ 1 });
        SP_CHECK_EQ(reach.sinks().size(), std::size_t{ 1 });
        SP_CHECK(reach.is_reachable_from_input(0x3000));

        const auto impactful = reach.impactful();
        SP_CHECK_EQ(impactful.size(), std::size_t{ 1 });
        if (!impactful.empty()) {
            const ReachabilityResult* r = impactful.front();
            SP_CHECK_EQ(r->sink, SinkKind::UnboundedCopy);
            SP_CHECK_EQ(r->effective_severity, SinkSeverity::High);
            SP_CHECK(r->sources.count(InputSource::CommandLine) == 1);

            // The call path is the evidence; without it the claim is
            // unverifiable.
            SP_CHECK_EQ(r->path.size(), std::size_t{ 3 });
            if (r->path.size() == 3) {
                SP_CHECK_EQ(r->path[0], core::VA{ 0x1000 });
                SP_CHECK_EQ(r->path[2], core::VA{ 0x3000 });
            }

            // Must always state what was not proven.
            SP_CHECK(!r->limitation.empty());
        }
    }

    SP_TEST("reachability: unreachable sink is downgraded, not hidden");
    {
        // Same strcpy, but nothing untrusted reaches it. A code-quality remark,
        // not a security finding - and it must never be reported as High.
        std::map<core::VA, Function> functions;
        functions[0x1000] = make_function(0x1000, {}, { 0x2000 });
        functions[0x2000] = make_function(0x2000, { "msvcrt.dll!strcpy" });

        CallGraph graph;
        graph.build(functions);

        Reachability reach;
        reach.analyze(functions, graph, options);

        SP_CHECK(!reach.is_reachable_from_input(0x2000));
        SP_CHECK_EQ(reach.impactful().size(), std::size_t{ 0 });

        // Still reported, so the inventory is complete.
        SP_CHECK_EQ(reach.results().size(), std::size_t{ 1 });
        if (!reach.results().empty()) {
            const ReachabilityResult& r = reach.results().front();
            SP_CHECK_EQ(r.base_severity, SinkSeverity::High);
            SP_CHECK_EQ(r.effective_severity, SinkSeverity::Low);
            SP_CHECK(!r.reachable_from_input);
            SP_CHECK(r.path.empty());
        }
    }

    SP_TEST("reachability: severity composition");
    {
        // Exposure is what promotes a finding. The same sink kind must not
        // report the same severity in both states.
        SP_CHECK_EQ(Reachability::compose_severity(SinkKind::UnboundedCopy, true),
                    SinkSeverity::High);
        SP_CHECK_EQ(Reachability::compose_severity(SinkKind::UnboundedCopy, false),
                    SinkSeverity::Low);
        SP_CHECK_EQ(Reachability::compose_severity(SinkKind::FileWrite, false),
                    SinkSeverity::Informational);
    }

    SP_TEST("reachability: source and sink in the same function");
    {
        std::map<core::VA, Function> functions;
        functions[0x1000] = make_function(0x1000,
            { "api-ms-win-core-file-l1-1-0.dll!ReadFile", "msvcrt.dll!memcpy" });

        CallGraph graph;
        graph.build(functions);

        Reachability reach;
        reach.analyze(functions, graph, options);

        SP_CHECK(reach.is_reachable_from_input(0x1000));
        if (!reach.results().empty()) {
            SP_CHECK(reach.results().front().sources.count(InputSource::File) == 1);
        }
    }

    SP_TEST("reachability: depth limit is honoured");
    {
        // A chain longer than max_depth must not report the far end as reachable
        // - past a few hops the claim stops meaning anything.
        std::map<core::VA, Function> functions;
        functions[0x1000] = make_function(0x1000, { "WS2_32.dll!recv" }, { 0x1001 });
        for (core::VA i = 1; i < 6; ++i) {
            functions[0x1000 + i] = make_function(0x1000 + i, {}, { 0x1001 + i });
        }
        functions[0x1006] = make_function(0x1006, { "msvcrt.dll!strcpy" });

        CallGraph graph;
        graph.build(functions);

        ReachabilityOptions shallow = options;
        shallow.max_depth = 2;

        Reachability reach;
        reach.analyze(functions, graph, shallow);
        SP_CHECK(!reach.is_reachable_from_input(0x1006));

        ReachabilityOptions deep = options;
        deep.max_depth = 10;
        reach.analyze(functions, graph, deep);
        SP_CHECK(reach.is_reachable_from_input(0x1006));
    }

    SP_TEST("reachability: cyclic call graph terminates");
    {
        // Mutual recursion between the source and an intermediate must not spin.
        std::map<core::VA, Function> functions;
        functions[0x1000] = make_function(0x1000, { "WS2_32.dll!recv" }, { 0x2000 });
        functions[0x2000] = make_function(0x2000, {}, { 0x1000, 0x3000 });
        functions[0x3000] = make_function(0x3000, { "msvcrt.dll!strcpy" }, { 0x2000 });

        CallGraph graph;
        graph.build(functions);

        Reachability reach;
        reach.analyze(functions, graph, options);
        SP_CHECK(reach.is_reachable_from_input(0x3000));
    }

    SP_TEST("reachability: empty input is safe");
    {
        std::map<core::VA, Function> functions;
        CallGraph graph;
        graph.build(functions);

        Reachability reach;
        reach.analyze(functions, graph, options);
        SP_CHECK(reach.results().empty());
        SP_CHECK(reach.impactful().empty());
        SP_CHECK(!reach.is_reachable_from_input(0x1000));
    }
}
