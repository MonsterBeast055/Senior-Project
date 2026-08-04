#include "test_harness.h"

#include "sp/disasm/CodeMap.h"

using namespace sp::core;
using namespace sp::disasm;

void test_code_map()
{
    SP_TEST("code map: stronger evidence is not overwritten by weaker");
    {
        CodeMap map;
        map.classify(0x1000, 0x1010, ByteClass::Code, Confidence::Certain,
                     ProvenanceKind::PeUnwindInfo);

        // A speculative sweep must not downgrade a certain classification.
        map.classify(0x1000, 0x1010, ByteClass::ProbablyCode, Confidence::Low,
                     ProvenanceKind::LinearSweep);

        SP_CHECK_EQ(map.class_of(0x1004), ByteClass::Code);
        SP_CHECK_EQ(map.confidence_of(0x1004), Confidence::Certain);
    }

    SP_TEST("code map: forced reclassification retracts a bad decode");
    {
        CodeMap map;
        map.classify(0x2000, 0x2020, ByteClass::Code, Confidence::Low,
                     ProvenanceKind::LinearSweep);
        map.reclassify_forced(0x2000, 0x2020, ByteClass::Data,
                              ProvenanceKind::UserSpecified);

        SP_CHECK_EQ(map.class_of(0x2008), ByteClass::Data);
        SP_CHECK_EQ(map.confidence_of(0x2008), Confidence::Certain);
    }

    SP_TEST("code map: unclaimed ranges are reported honestly");
    {
        CodeMap map;
        map.classify(0x1000, 0x1010, ByteClass::Code, Confidence::High,
                     ProvenanceKind::DirectCallTarget);
        map.classify(0x1020, 0x1030, ByteClass::Code, Confidence::High,
                     ProvenanceKind::DirectCallTarget);

        const auto gaps = map.unclaimed_ranges(0x1000, 0x1040);
        SP_CHECK_EQ(gaps.size(), std::size_t{ 2 });
        if (gaps.size() == 2) {
            SP_CHECK_EQ(gaps[0].start, VA{ 0x1010 });
            SP_CHECK_EQ(gaps[0].end, VA{ 0x1020 });
            SP_CHECK_EQ(gaps[1].start, VA{ 0x1030 });
            SP_CHECK_EQ(gaps[1].end, VA{ 0x1040 });
        }
    }

    SP_TEST("code map: coverage statistic");
    {
        CodeMap map;
        map.classify(0x1000, 0x1020, ByteClass::Code, Confidence::High,
                     ProvenanceKind::DirectCallTarget);
        // Half of [0x1000, 0x1040) is code.
        const double coverage = map.code_coverage(0x1000, 0x1040);
        SP_CHECK(coverage > 0.49 && coverage < 0.51);
    }
}
