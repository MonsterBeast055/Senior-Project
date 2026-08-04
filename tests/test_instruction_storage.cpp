#include "test_harness.h"

#include "sp/disasm/InstructionStorage.h"

using namespace sp::core;
using namespace sp::disasm;

namespace {

InstructionInfo make_insn(VA address, std::uint16_t size, FlowKind flow)
{
    InstructionInfo insn;
    insn.address = address;
    insn.size = size;
    insn.flow = flow;
    insn.mnemonic = "nop";
    return insn;
}

} // namespace

void test_instruction_storage()
{
    SP_TEST("instruction storage: lookup by exact address");
    {
        InstructionStorage storage;
        storage.add(make_insn(0x1000, 4, FlowKind::Sequential));
        storage.add(make_insn(0x1004, 2, FlowKind::Return));

        SP_CHECK(storage.contains(0x1000));
        SP_CHECK(!storage.contains(0x1002));
        SP_CHECK_EQ(storage.size(), std::size_t{ 2 });
    }

    SP_TEST("instruction storage: covering() finds mid-instruction addresses");
    {
        // A branch landing mid-instruction is a strong obfuscation signal, so it
        // must be detectable rather than silently missed.
        InstructionStorage storage;
        storage.add(make_insn(0x1000, 5, FlowKind::Sequential));

        const InstructionInfo* covering = storage.covering(0x1002);
        SP_CHECK(covering != nullptr);
        if (covering != nullptr) {
            SP_CHECK_EQ(covering->address, VA{ 0x1000 });
        }
        SP_CHECK(storage.covering(0x1005) == nullptr);
    }

    SP_TEST("instruction storage: range removal supports retraction");
    {
        InstructionStorage storage;
        storage.add(make_insn(0x1000, 2, FlowKind::Sequential));
        storage.add(make_insn(0x1002, 2, FlowKind::Sequential));
        storage.add(make_insn(0x1004, 2, FlowKind::Sequential));

        SP_CHECK_EQ(storage.remove_range(0x1000, 0x1004), std::size_t{ 2 });
        SP_CHECK_EQ(storage.size(), std::size_t{ 1 });
        SP_CHECK(storage.contains(0x1004));
    }

    SP_TEST("instruction storage: flow classification predicates");
    {
        const auto ret = make_insn(0x1000, 1, FlowKind::Return);
        SP_CHECK(ret.is_return());
        SP_CHECK(!ret.has_fall_through());
        SP_CHECK(ret.terminates_block());

        const auto call = make_insn(0x1000, 5, FlowKind::Call);
        SP_CHECK(call.is_call());
        // A call returns, so it does not end a basic block.
        SP_CHECK(call.has_fall_through());
        SP_CHECK(!call.terminates_block());

        const auto jcc = make_insn(0x1000, 2, FlowKind::ConditionalJump);
        SP_CHECK(jcc.is_conditional_jump());
        SP_CHECK(jcc.has_fall_through());
        SP_CHECK(jcc.terminates_block());

        const auto jmp = make_insn(0x1000, 5, FlowKind::UnconditionalJump);
        SP_CHECK(!jmp.has_fall_through());
        SP_CHECK(jmp.terminates_block());
    }
}
