#include "test_harness.h"

#include "sp/analysis/CFGBuilder.h"
#include "sp/db/EntityId.h"
#include "sp/db/FactStore.h"
#include "sp/disasm/InstructionStorage.h"

#include <map>
#include <string>
#include <vector>

using namespace sp;
using namespace sp::analysis;
using sp::disasm::FlowKind;
using sp::disasm::InstructionInfo;
using sp::disasm::InstructionStorage;

namespace {

// Synthetic instruction builder. Sizes are fictional but consistent, which is
// all the CFG builder cares about - it never looks at bytes.
InstructionInfo insn(core::VA address,
                     std::uint16_t size,
                     FlowKind flow,
                     const std::string& mnemonic = "nop")
{
    InstructionInfo i;
    i.address = address;
    i.size = size;
    i.flow = flow;
    i.mnemonic = mnemonic;
    if (i.has_fall_through()) {
        i.fall_through = address + size;
    }
    return i;
}

InstructionInfo branch(core::VA address,
                       std::uint16_t size,
                       FlowKind flow,
                       core::VA target,
                       const std::string& mnemonic)
{
    InstructionInfo i = insn(address, size, flow, mnemonic);
    i.direct_target = target;
    return i;
}

InstructionInfo indirect(core::VA address,
                         std::uint16_t size,
                         FlowKind flow,
                         const std::string& mnemonic)
{
    InstructionInfo i = insn(address, size, flow, mnemonic);
    i.is_indirect = true;
    return i;
}

db::FactStore make_facts()
{
    db::FactStore facts;
    facts.set_arch(core::Arch::X86_64);
    return facts;
}

// Build one function with the given entry set treated as known function starts.
core::Result<Function> build(const InstructionStorage& code,
                             core::VA entry,
                             const std::vector<core::VA>& function_entries,
                             const std::set<core::VA>& noreturn = {},
                             const std::map<core::VA, core::VA>& extents = {})
{
    static db::FactStore facts = make_facts();
    db::EntityIdAllocator ids;
    CFGBuilder builder;

    const std::set<core::VA> entry_set(function_entries.begin(), function_entries.end());
    const std::set<core::VA> leaders = CFGBuilder::compute_leaders(code, function_entries);

    CFGBuildContext context;
    context.function_entries = &entry_set;
    context.leaders = &leaders;
    context.noreturn_functions = &noreturn;
    context.function_extents = &extents;

    return builder.build_function(facts, code, entry, context, CFGBuildOptions{}, ids);
}

} // namespace

void test_cfg_builder()
{
    SP_TEST("cfg builder: a call does not split a basic block");
    {
        // 0x1000 mov ; 0x1004 call ; 0x1009 mov ; 0x100d ret
        // The call returns, so all four instructions belong to one block.
        InstructionStorage code;
        code.add(insn(0x1000, 4, FlowKind::Sequential, "mov"));
        code.add(branch(0x1004, 5, FlowKind::Call, 0x2000, "call"));
        code.add(insn(0x1009, 4, FlowKind::Sequential, "mov"));
        code.add(insn(0x100D, 1, FlowKind::Return, "ret"));

        auto result = build(code, 0x1000, { 0x1000, 0x2000 });
        SP_CHECK(result.ok());
        if (result.ok()) {
            const Function& f = result.value();
            SP_CHECK_EQ(f.cfg.block_count(), std::size_t{ 1 });
            SP_CHECK_EQ(f.instruction_count, std::size_t{ 4 });

            // The call target is recorded as a callee, not as a CFG edge.
            SP_CHECK_EQ(f.callees.size(), std::size_t{ 1 });
            SP_CHECK_EQ(f.cfg.edge_count(), std::size_t{ 0 });
            SP_CHECK(f.returns);
        }
    }

    SP_TEST("cfg builder: a call to a noreturn function does split the block");
    {
        // Same shape, but the callee never returns, so the trailing mov is not
        // reachable through this path and must not join the block.
        InstructionStorage code;
        code.add(insn(0x1000, 4, FlowKind::Sequential, "mov"));
        code.add(branch(0x1004, 5, FlowKind::Call, 0x2000, "call"));
        code.add(insn(0x1009, 4, FlowKind::Sequential, "mov"));
        code.add(insn(0x100D, 1, FlowKind::Return, "ret"));

        auto result = build(code, 0x1000, { 0x1000, 0x2000 }, { 0x2000 });
        SP_CHECK(result.ok());
        if (result.ok()) {
            const Function& f = result.value();
            SP_CHECK_EQ(f.cfg.block_count(), std::size_t{ 1 });
            SP_CHECK_EQ(f.instruction_count, std::size_t{ 2 });
            SP_CHECK_EQ(f.cfg.edge_count(), std::size_t{ 0 });

            // No ret is reachable, so the function does not return.
            SP_CHECK(!f.returns);
        }
    }

    SP_TEST("cfg builder: conditional jump yields taken and fall-through edges");
    {
        // 0x1000 cmp ; 0x1002 je 0x1010 ; 0x1004 mov ; 0x1008 ret ; 0x1010 ret
        InstructionStorage code;
        code.add(insn(0x1000, 2, FlowKind::Sequential, "cmp"));
        code.add(branch(0x1002, 2, FlowKind::ConditionalJump, 0x1010, "je"));
        code.add(insn(0x1004, 4, FlowKind::Sequential, "mov"));
        code.add(insn(0x1008, 1, FlowKind::Return, "ret"));
        code.add(insn(0x1010, 1, FlowKind::Return, "ret"));

        auto result = build(code, 0x1000, { 0x1000 });
        SP_CHECK(result.ok());
        if (result.ok()) {
            const Function& f = result.value();

            // entry block, fall-through block at 0x1004, target block at 0x1010
            SP_CHECK_EQ(f.cfg.block_count(), std::size_t{ 3 });
            SP_CHECK_EQ(f.cfg.edge_count(), std::size_t{ 2 });

            const BasicBlock* head = f.cfg.block_at(0x1000);
            SP_CHECK(head != nullptr);
            if (head != nullptr) {
                SP_CHECK_EQ(head->successors.size(), std::size_t{ 2 });
                bool has_taken = false;
                bool has_fall = false;
                for (const Edge& e : head->successors) {
                    if (e.kind == EdgeKind::Taken && e.target == 0x1010) has_taken = true;
                    if (e.kind == EdgeKind::FallThrough && e.target == 0x1004) has_fall = true;
                }
                SP_CHECK(has_taken);
                SP_CHECK(has_fall);
            }

            // The not-taken address must have become a leader, otherwise the
            // entry block would have run straight through the branch.
            SP_CHECK(f.cfg.block_at(0x1004) != nullptr);
        }
    }

    SP_TEST("cfg builder: unresolved indirect jump is declared, not hidden");
    {
        // A switch table we cannot resolve. The block must say its exit is
        // unknown rather than silently appear to be a dead end.
        InstructionStorage code;
        code.add(insn(0x1000, 4, FlowKind::Sequential, "mov"));
        code.add(indirect(0x1004, 7, FlowKind::UnconditionalJump, "jmp"));

        auto result = build(code, 0x1000, { 0x1000 });
        SP_CHECK(result.ok());
        if (result.ok()) {
            const Function& f = result.value();
            const BasicBlock* head = f.cfg.block_at(0x1000);
            SP_CHECK(head != nullptr);
            if (head != nullptr) {
                SP_CHECK(head->has_unresolved_exit);
                SP_CHECK_EQ(head->successors.size(), std::size_t{ 0 });
            }
        }
    }

    SP_TEST("cfg builder: resolved jump table produces indirect edges");
    {
        InstructionStorage code;
        InstructionInfo table_jump = indirect(0x1000, 7, FlowKind::UnconditionalJump, "jmp");
        table_jump.resolved_targets = { 0x1010, 0x1020 };
        code.add(table_jump);
        code.add(insn(0x1010, 1, FlowKind::Return, "ret"));
        code.add(insn(0x1020, 1, FlowKind::Return, "ret"));

        auto result = build(code, 0x1000, { 0x1000 });
        SP_CHECK(result.ok());
        if (result.ok()) {
            const Function& f = result.value();
            SP_CHECK_EQ(f.cfg.block_count(), std::size_t{ 3 });
            SP_CHECK_EQ(f.cfg.edge_count(), std::size_t{ 2 });
            const BasicBlock* head = f.cfg.block_at(0x1000);
            if (head != nullptr && head->successors.size() == 2) {
                SP_CHECK_EQ(head->successors[0].kind, EdgeKind::IndirectJump);
                SP_CHECK(!head->has_unresolved_exit);
            }
        }
    }

    SP_TEST("cfg builder: tail call is a boundary, not an edge");
    {
        // 0x1000 mov ; 0x1004 jmp 0x2000, where 0x2000 is another function.
        // Following that jump would swallow the whole of function 0x2000.
        InstructionStorage code;
        code.add(insn(0x1000, 4, FlowKind::Sequential, "mov"));
        code.add(branch(0x1004, 5, FlowKind::UnconditionalJump, 0x2000, "jmp"));
        code.add(insn(0x2000, 4, FlowKind::Sequential, "mov"));
        code.add(insn(0x2004, 1, FlowKind::Return, "ret"));

        auto result = build(code, 0x1000, { 0x1000, 0x2000 });
        SP_CHECK(result.ok());
        if (result.ok()) {
            const Function& f = result.value();
            SP_CHECK_EQ(f.cfg.block_count(), std::size_t{ 1 });
            SP_CHECK_EQ(f.cfg.edge_count(), std::size_t{ 0 });

            // Recorded as a call relationship instead.
            SP_CHECK_EQ(f.callees.size(), std::size_t{ 1 });
            if (f.callees.size() == 1) {
                SP_CHECK_EQ(f.callees[0], core::VA{ 0x2000 });
            }

            // Function 0x2000's code must not have been absorbed.
            SP_CHECK_EQ(f.instruction_count, std::size_t{ 2 });
            SP_CHECK(f.extent_end <= 0x2000);
        }
    }

    SP_TEST("cfg builder: intra-function jump is a normal edge");
    {
        // Same shape as the tail call, but 0x2000 is not a function entry - so
        // it is an ordinary jump inside this function and must be followed.
        InstructionStorage code;
        code.add(insn(0x1000, 4, FlowKind::Sequential, "mov"));
        code.add(branch(0x1004, 5, FlowKind::UnconditionalJump, 0x2000, "jmp"));
        code.add(insn(0x2000, 4, FlowKind::Sequential, "mov"));
        code.add(insn(0x2004, 1, FlowKind::Return, "ret"));

        auto result = build(code, 0x1000, { 0x1000 });
        SP_CHECK(result.ok());
        if (result.ok()) {
            const Function& f = result.value();
            SP_CHECK_EQ(f.cfg.block_count(), std::size_t{ 2 });
            SP_CHECK_EQ(f.cfg.edge_count(), std::size_t{ 1 });
            SP_CHECK_EQ(f.instruction_count, std::size_t{ 4 });
            SP_CHECK(f.callees.empty());
        }
    }

    SP_TEST("cfg builder: loop back-edge is wired");
    {
        // 0x1000 inc ; 0x1002 cmp ; 0x1004 jne 0x1000 ; 0x1006 ret
        InstructionStorage code;
        code.add(insn(0x1000, 2, FlowKind::Sequential, "inc"));
        code.add(insn(0x1002, 2, FlowKind::Sequential, "cmp"));
        code.add(branch(0x1004, 2, FlowKind::ConditionalJump, 0x1000, "jne"));
        code.add(insn(0x1006, 1, FlowKind::Return, "ret"));

        auto result = build(code, 0x1000, { 0x1000 });
        SP_CHECK(result.ok());
        if (result.ok()) {
            const Function& f = result.value();
            SP_CHECK_EQ(f.cfg.block_count(), std::size_t{ 2 });

            const BasicBlock* head = f.cfg.block_at(0x1000);
            SP_CHECK(head != nullptr);
            if (head != nullptr) {
                // The back edge makes the header its own predecessor.
                bool self_referencing = false;
                for (core::VA pred : head->predecessors) {
                    if (pred == 0x1000) self_referencing = true;
                }
                SP_CHECK(self_referencing);
            }
        }
    }

    SP_TEST("cfg builder: import thunk is flagged");
    {
        InstructionStorage code;
        code.add(indirect(0x1000, 6, FlowKind::UnconditionalJump, "jmp"));

        auto result = build(code, 0x1000, { 0x1000 });
        SP_CHECK(result.ok());
        if (result.ok()) {
            const Function& f = result.value();
            SP_CHECK(f.is_thunk);
            SP_CHECK(f.is_imported_stub);
        }
    }

    SP_TEST("cfg builder: entry with no decoded instruction fails cleanly");
    {
        InstructionStorage code;
        code.add(insn(0x1000, 1, FlowKind::Return, "ret"));

        auto result = build(code, 0x9999, { 0x1000 });
        SP_CHECK(!result.ok());
        if (!result.ok()) {
            SP_CHECK_EQ(result.error().code, core::ErrorCode::InvalidAddress);
        }
    }

    SP_TEST("cfg builder: fall-through into another function is a boundary");
    {
        // The catastrophic case. Function A ends with a call to something we did
        // not recognise as noreturn, followed by int3 filler - so control appears
        // to fall through into function B's entry. Following that as an edge
        // makes A absorb B, then B's own tail falls into C, and the cascade can
        // swallow most of the binary.
        InstructionStorage code;
        // Function A at 0x1000
        code.add(insn(0x1000, 4, FlowKind::Sequential, "mov"));
        code.add(branch(0x1004, 5, FlowKind::Call, 0x5000, "call"));
        code.add(insn(0x1009, 1, FlowKind::Interrupt, "int3"));
        // Function B at 0x100a - immediately after, as the linker laid it out
        code.add(insn(0x100A, 4, FlowKind::Sequential, "mov"));
        code.add(insn(0x100E, 1, FlowKind::Return, "ret"));

        auto result = build(code, 0x1000, { 0x1000, 0x100A, 0x5000 });
        SP_CHECK(result.ok());
        if (result.ok()) {
            const Function& f = result.value();

            // A must contain only its own three instructions.
            SP_CHECK_EQ(f.instruction_count, std::size_t{ 3 });
            SP_CHECK_EQ(f.cfg.block_count(), std::size_t{ 1 });
            SP_CHECK_EQ(f.cfg.edge_count(), std::size_t{ 0 });

            // B's code must not have been absorbed.
            SP_CHECK(f.cfg.block_at(0x100A) == nullptr);
            SP_CHECK(f.extent_end <= 0x100A);
        }
    }

    SP_TEST("cfg builder: conditional fall-through into another function is a boundary");
    {
        // Same hazard through the not-taken path of a conditional branch.
        InstructionStorage code;
        code.add(branch(0x1000, 6, FlowKind::ConditionalJump, 0x2000, "je"));
        code.add(insn(0x1006, 1, FlowKind::Return, "ret"));   // function B entry
        code.add(insn(0x2000, 1, FlowKind::Return, "ret"));

        auto result = build(code, 0x1000, { 0x1000, 0x1006, 0x2000 });
        SP_CHECK(result.ok());
        if (result.ok()) {
            const Function& f = result.value();
            // Only the taken edge survives; the fall-through crosses into B.
            SP_CHECK_EQ(f.cfg.edge_count(), std::size_t{ 1 });
            const BasicBlock* head = f.cfg.block_at(0x1000);
            if (head != nullptr && head->successors.size() == 1) {
                SP_CHECK_EQ(head->successors[0].kind, EdgeKind::Taken);
                SP_CHECK_EQ(head->successors[0].target, core::VA{ 0x2000 });
            }
            SP_CHECK(f.cfg.block_at(0x1006) == nullptr);
        }
    }

    SP_TEST("cfg builder: fall-through within a function is still followed");
    {
        // Guard against over-correcting: an ordinary leader that is NOT a
        // function entry must still get its fall-through edge.
        InstructionStorage code;
        code.add(branch(0x1000, 6, FlowKind::ConditionalJump, 0x100A, "je"));
        code.add(insn(0x1006, 4, FlowKind::Sequential, "mov"));
        code.add(insn(0x100A, 1, FlowKind::Return, "ret"));

        auto result = build(code, 0x1000, { 0x1000 });
        SP_CHECK(result.ok());
        if (result.ok()) {
            const Function& f = result.value();
            SP_CHECK_EQ(f.cfg.edge_count(), std::size_t{ 3 });
            SP_CHECK_EQ(f.instruction_count, std::size_t{ 3 });
            SP_CHECK(f.cfg.block_at(0x1006) != nullptr);
        }
    }

    SP_TEST("cfg builder: .pdata extent caps the walk when nothing else can");
    {
        // The hard case from real data: a stretch of code where discovery found
        // no other function entries at all, because everything in it is reached
        // through function pointers. There is no next-function address to infer
        // a boundary from, so without .pdata the walk runs on until it happens
        // to hit a return - one 45KB region of notepad.exe came out as a single
        // 1620-block function this way.
        InstructionStorage code;
        code.add(insn(0x1000, 4, FlowKind::Sequential, "mov"));
        code.add(branch(0x1004, 5, FlowKind::UnconditionalJump, 0x100A, "jmp"));
        // Beyond the declared end - belongs to whatever comes next.
        code.add(insn(0x100A, 4, FlowKind::Sequential, "mov"));
        code.add(insn(0x100E, 1, FlowKind::Return, "ret"));

        // .pdata says this function is [0x1000, 0x1009).
        const std::map<core::VA, core::VA> extents{ { 0x1000, 0x1009 } };

        auto result = build(code, 0x1000, { 0x1000 }, {}, extents);
        SP_CHECK(result.ok());
        if (result.ok()) {
            const Function& f = result.value();
            SP_CHECK_EQ(f.instruction_count, std::size_t{ 2 });
            SP_CHECK_EQ(f.cfg.block_count(), std::size_t{ 1 });
            SP_CHECK_EQ(f.cfg.edge_count(), std::size_t{ 0 });
            SP_CHECK(f.cfg.block_at(0x100A) == nullptr);
            SP_CHECK(f.extent_end <= 0x1009);

            // The out-of-range jump is recorded as a call relationship.
            SP_CHECK_EQ(f.callees.size(), std::size_t{ 1 });
        }
    }

    SP_TEST("cfg builder: jumps inside the declared extent are still followed");
    {
        // Guard against over-correcting.
        InstructionStorage code;
        code.add(branch(0x1000, 4, FlowKind::UnconditionalJump, 0x1008, "jmp"));
        code.add(insn(0x1008, 1, FlowKind::Return, "ret"));

        const std::map<core::VA, core::VA> extents{ { 0x1000, 0x1010 } };

        auto result = build(code, 0x1000, { 0x1000 }, {}, extents);
        SP_CHECK(result.ok());
        if (result.ok()) {
            const Function& f = result.value();
            SP_CHECK_EQ(f.cfg.block_count(), std::size_t{ 2 });
            SP_CHECK_EQ(f.cfg.edge_count(), std::size_t{ 1 });
            SP_CHECK(f.callees.empty());
        }
    }

    SP_TEST("cfg builder: leaders include entries, targets and fall-throughs");
    {
        InstructionStorage code;
        code.add(branch(0x1000, 2, FlowKind::ConditionalJump, 0x1010, "je"));
        code.add(insn(0x1002, 1, FlowKind::Return, "ret"));
        code.add(insn(0x1010, 1, FlowKind::Return, "ret"));

        const auto leaders = CFGBuilder::compute_leaders(code, { 0x1000, 0x2000 });

        SP_CHECK(leaders.count(0x1000) == 1);  // function entry
        SP_CHECK(leaders.count(0x2000) == 1);  // other function entry
        SP_CHECK(leaders.count(0x1010) == 1);  // branch target
        SP_CHECK(leaders.count(0x1002) == 1);  // conditional fall-through
    }
}
