#include "test_harness.h"

#include "sp/core/Provenance.h"

using namespace sp::core;

void test_provenance()
{
    SP_TEST("provenance: strongest evidence wins");
    {
        ProvenanceSet set;
        set.add({ ProvenanceKind::LinearSweep, kInvalidVA, Confidence::None, false });
        SP_CHECK_EQ(set.effective_confidence(), Confidence::Low);

        set.add({ ProvenanceKind::PeUnwindInfo, kInvalidVA, Confidence::None, false });
        SP_CHECK_EQ(set.effective_confidence(), Confidence::Certain);
    }

    SP_TEST("provenance: retraction drops a belief but keeps the trail");
    {
        ProvenanceSet set;
        set.add({ ProvenanceKind::LinearSweep, kInvalidVA, Confidence::None, false });
        set.add({ ProvenanceKind::DirectCallTarget, 0x1000, Confidence::None, false });
        SP_CHECK_EQ(set.effective_confidence(), Confidence::High);

        set.retract_kind(ProvenanceKind::DirectCallTarget);
        SP_CHECK_EQ(set.effective_confidence(), Confidence::Low);

        // The retracted record is still present for audit.
        SP_CHECK_EQ(set.records().size(), std::size_t{ 2 });
        SP_CHECK(!set.has_kind(ProvenanceKind::DirectCallTarget));
    }

    SP_TEST("provenance: ground truth outranks heuristics");
    {
        SP_CHECK(base_confidence(ProvenanceKind::PeUnwindInfo)
                 > base_confidence(ProvenanceKind::ProloguePattern));
        SP_CHECK(base_confidence(ProvenanceKind::ProloguePattern)
                 > base_confidence(ProvenanceKind::LinearSweep));
        SP_CHECK(base_confidence(ProvenanceKind::UserSpecified)
                 > base_confidence(ProvenanceKind::AiInferred));
    }
}
