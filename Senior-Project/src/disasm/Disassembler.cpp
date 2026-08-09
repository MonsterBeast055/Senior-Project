#include "sp/disasm/Disassembler.h"

#include "sp/core/Log.h"

#include <algorithm>
#include <sstream>

// Capstone is confined to this translation unit; Impl hides csh and cs_insn so
// no other module needs the dependency.
#include <capstone/capstone.h>

namespace sp::disasm {
namespace {

// Longest possible x86-64 instruction. Any decode needs at most this many bytes.
constexpr std::size_t kMaxInstructionBytes = 15;

// A padding run shorter than this is more likely alignment inside a function
// than a gap between functions, so we leave it alone.
constexpr std::size_t kMinPaddingRun = 2;

std::string hex(std::uint64_t value)
{
    std::ostringstream out;
    out << "0x" << std::hex << value;
    return out.str();
}

bool is_padding_byte(std::uint8_t b)
{
    // int3 (0xCC) and nop (0x90) are the usual inter-function fillers; zero
    // shows up in zero-padded sections.
    return b == 0xCC || b == 0x90 || b == 0x00;
}

} // namespace

struct Disassembler::Impl {
    csh handle = 0;
    bool open = false;

    // Reused across decodes rather than cs_malloc'd per instruction.
    cs_insn* scratch = nullptr;

    ~Impl()
    {
        if (scratch != nullptr) {
            cs_free(scratch, 1);
            scratch = nullptr;
        }
        if (open) {
            cs_close(&handle);
            open = false;
        }
    }

    // How control leaves this instruction.
    FlowKind classify(const cs_insn* insn) const
    {
        if (cs_insn_group(handle, insn, CS_GRP_RET)) {
            return FlowKind::Return;
        }
        if (cs_insn_group(handle, insn, CS_GRP_CALL)) {
            return FlowKind::Call;
        }
        if (cs_insn_group(handle, insn, CS_GRP_JUMP)) {
            // Everything in the jump group except JMP itself is conditional:
            // jcc, loop, loope/loopne, jrcxz.
            return (insn->id == X86_INS_JMP) ? FlowKind::UnconditionalJump
                                             : FlowKind::ConditionalJump;
        }
        if (insn->id == X86_INS_HLT || insn->id == X86_INS_UD2) {
            return FlowKind::Halt;
        }
        if (cs_insn_group(handle, insn, CS_GRP_INT)
            || cs_insn_group(handle, insn, CS_GRP_IRET)) {
            return FlowKind::Interrupt;
        }
        return FlowKind::Sequential;
    }

    // First operand, which for a branch or call is the destination.
    const cs_x86_op* first_operand(const cs_insn* insn) const
    {
        if (insn->detail == nullptr || insn->detail->x86.op_count == 0) {
            return nullptr;
        }
        return &insn->detail->x86.operands[0];
    }

    // Absolute address of a statically-known memory operand, if any.
    //
    // Two forms are resolvable:
    //   rip-relative  [rip + disp]  -> next_instruction_address + disp
    //   absolute      [disp]        -> disp, with no base or index register
    //
    // Anything involving a runtime register value is not knowable here and is
    // deliberately left absent rather than guessed at.
    std::optional<core::VA> memory_reference(const cs_insn* insn) const
    {
        if (insn->detail == nullptr) {
            return std::nullopt;
        }
        const cs_x86& detail = insn->detail->x86;

        for (std::uint8_t i = 0; i < detail.op_count; ++i) {
            const cs_x86_op& op = detail.operands[i];
            if (op.type != X86_OP_MEM) {
                continue;
            }

            if (op.mem.base == X86_REG_RIP) {
                // Capstone reports the displacement relative to the end of the
                // instruction, which is what the CPU uses.
                return static_cast<core::VA>(
                    static_cast<std::int64_t>(insn->address) + insn->size + op.mem.disp);
            }

            if (op.mem.base == X86_REG_INVALID && op.mem.index == X86_REG_INVALID
                && op.mem.disp != 0) {
                // Absolute displacement, the usual form in 32-bit code.
                return static_cast<core::VA>(op.mem.disp);
            }
        }
        return std::nullopt;
    }
};

Disassembler::Disassembler() : impl_(std::make_unique<Impl>()) {}
Disassembler::~Disassembler() = default;

core::Status Disassembler::initialize(const db::FactStore& facts)
{
    if (impl_->open) {
        return core::Status::success();
    }

    cs_mode mode;
    switch (facts.arch()) {
    case core::Arch::X86_64: mode = CS_MODE_64; break;
    case core::Arch::X86:    mode = CS_MODE_32; break;
    default:
        return core::Error(core::ErrorCode::UnsupportedArchitecture,
                           "no Capstone mode for architecture");
    }

    if (!cs_support(CS_ARCH_X86)) {
        return core::Error(core::ErrorCode::DisassemblerInitFailed,
                           "this Capstone build lacks x86 support");
    }

    if (cs_open(CS_ARCH_X86, mode, &impl_->handle) != CS_ERR_OK) {
        return core::Error(core::ErrorCode::DisassemblerInitFailed, "cs_open failed");
    }
    impl_->open = true;

    // Detail mode is mandatory here. Without it there are no instruction groups
    // and no operand data, which would force us to classify control flow by
    // string-matching op_str - fragile and wrong on edge cases.
    if (cs_option(impl_->handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
        return core::Error(core::ErrorCode::DisassemblerInitFailed,
                           "could not enable Capstone detail mode");
    }

    impl_->scratch = cs_malloc(impl_->handle);
    if (impl_->scratch == nullptr) {
        return core::Error(core::ErrorCode::DisassemblerInitFailed, "cs_malloc failed");
    }

    return core::Status::success();
}

core::Result<InstructionInfo> Disassembler::decode_one(const db::FactStore& facts,
                                                      core::VA address,
                                                      db::EntityIdAllocator& ids)
{
    if (!impl_->open) {
        return core::Error(core::ErrorCode::DisassemblerInitFailed, "not initialized");
    }

    // Ask for the longest possible instruction, but accept a short tail at the
    // end of a section.
    std::size_t available = kMaxInstructionBytes;
    const std::uint8_t* bytes = facts.bytes_at(address, available);
    while (bytes == nullptr && available > 1) {
        --available;
        bytes = facts.bytes_at(address, available);
    }
    if (bytes == nullptr) {
        return core::Error(core::ErrorCode::InvalidAddress,
                           "no file-backed bytes at " + hex(address));
    }

    const std::uint8_t* cursor = bytes;
    std::size_t remaining = available;
    std::uint64_t cursor_address = address;

    if (!cs_disasm_iter(impl_->handle, &cursor, &remaining, &cursor_address, impl_->scratch)) {
        return core::Error(core::ErrorCode::DecodeFailed,
                           "cannot decode at " + hex(address));
    }

    const cs_insn* raw = impl_->scratch;

    InstructionInfo info;
    info.id = ids.allocate(db::EntityKind::Instruction);
    info.address = raw->address;
    info.size = static_cast<std::uint16_t>(raw->size);
    info.mnemonic = raw->mnemonic;
    info.op_str = raw->op_str;
    info.bytes.assign(raw->bytes, raw->bytes + raw->size);
    info.flow = impl_->classify(raw);

    if (info.is_jump() || info.is_call()) {
        const cs_x86_op* target = impl_->first_operand(raw);
        if (target != nullptr && target->type == X86_OP_IMM) {
            // Capstone has already resolved rip-relative displacement into an
            // absolute address for immediate branch operands.
            info.direct_target = static_cast<core::VA>(target->imm);
        } else {
            // Register or memory operand: destination is computed at runtime and
            // is not knowable here. Recorded honestly rather than guessed.
            info.is_indirect = true;
        }
    }

    // Statically-known memory operand target. Feeds string extraction and, for
    // `call qword [rip+N]`, IAT-slot resolution to a named import.
    info.memory_reference = impl_->memory_reference(raw);

    if (info.has_fall_through()) {
        info.fall_through = info.end_address();
    }

    return info;
}

void Disassembler::seed_from_facts(const db::FactStore& facts, DecodeQueue& queue)
{
    // Trusted sources only. The queue is a max-heap on confidence, so certain
    // evidence claims bytes before any speculation gets a chance.
    if (facts.entry_point() != core::kInvalidVA) {
        queue.push({ facts.entry_point(), core::ProvenanceKind::EntryPoint,
                     core::kInvalidVA, core::Confidence::Certain });
    }
    for (core::VA va : facts.unwind_function_starts()) {
        queue.push({ va, core::ProvenanceKind::PeUnwindInfo,
                     core::kInvalidVA, core::Confidence::Certain });
    }
    for (core::VA va : facts.tls_callbacks()) {
        queue.push({ va, core::ProvenanceKind::TlsCallback,
                     core::kInvalidVA, core::Confidence::Certain });
    }
    for (const auto& sym : facts.exports()) {
        if (!sym.is_forwarder && sym.address != core::kInvalidVA) {
            queue.push({ sym.address, core::ProvenanceKind::PeExport,
                         core::kInvalidVA, core::Confidence::Certain });
        }
    }
}

core::Status Disassembler::decode_block(const db::FactStore& facts,
                                       core::VA address,
                                       db::EntityIdAllocator& ids,
                                       InstructionStorage& out,
                                       CodeMap& map,
                                       DecodeQueue& queue)
{
    if (!impl_->open) {
        return core::Error(core::ErrorCode::DisassemblerInitFailed, "not initialized");
    }

    const core::ProvenanceKind reason = core::ProvenanceKind::FallThrough;
    core::VA cursor = address;

    while (true) {
        if (!facts.address_space().is_executable(cursor)) {
            break;
        }

        // Already decoded: another path reached here first, so stop rather than
        // duplicate work.
        if (out.contains(cursor)) {
            break;
        }

        // Refuse to decode bytes that a stronger pass has already called data.
        const core::ByteClass existing = map.class_of(cursor);
        if (existing == core::ByteClass::Data || existing == core::ByteClass::Padding) {
            break;
        }

        auto decoded = decode_one(facts, cursor, ids);
        if (!decoded.ok()) {
            ++stats_.decode_failures;
            break;
        }

        InstructionInfo info = std::move(decoded.value());
        info.provenance.add({ reason, cursor, core::Confidence::High, false });

        const core::VA next = info.end_address();
        map.classify(cursor, next, core::ByteClass::Code,
                     core::Confidence::High, reason);

        // Queue branch and call destinations before moving on, so the worklist
        // widens as we go. Provenance records which kind of edge found them.
        if (info.direct_target.has_value()) {
            const core::ProvenanceKind edge = info.is_call()
                ? core::ProvenanceKind::DirectCallTarget
                : core::ProvenanceKind::DirectJumpTarget;
            queue.push({ *info.direct_target, edge, cursor,
                         core::base_confidence(edge) });
        }
        for (core::VA resolved : info.resolved_targets) {
            queue.push({ resolved, core::ProvenanceKind::JumpTableEntry, cursor,
                         core::Confidence::High });
        }

        const bool stop = !info.has_fall_through();
        out.add(std::move(info));
        ++stats_.instructions_decoded;

        if (stop) {
            break;
        }
        cursor = next;
    }

    return core::Status::success();
}

core::Status Disassembler::run(const db::FactStore& facts,
                               const DisassemblyOptions& options,
                               db::EntityIdAllocator& ids,
                               InstructionStorage& out_instructions,
                               CodeMap& out_map)
{
    if (!impl_->open) {
        if (auto status = initialize(facts); !status.ok()) {
            return status;
        }
    }

    stats_ = DisassemblyStats{};

    DecodeQueue queue;
    seed_from_facts(facts, queue);

    // --- Pass 1: recursive descent from trusted entry points ---------------
    if (options.recursive_descent) {
        DecodeRequest request;
        while (queue.pop(request)) {
            if (options.max_instructions != 0
                && stats_.instructions_decoded >= options.max_instructions) {
                core::log_warn("instruction limit reached; stopping descent");
                break;
            }
            const std::size_t before = stats_.instructions_decoded;
            decode_block(facts, request.address, ids, out_instructions, out_map, queue);
            stats_.from_recursive_descent += stats_.instructions_decoded - before;
        }
    }

    // --- Pass 2: padding ---------------------------------------------------
    // Claim filler runs before the sweep sees them, otherwise a run of 0xCC
    // decodes as a wall of int3 instructions that look like real code.
    if (options.detect_padding) {
        for (const auto& section : facts.address_space().sections()) {
            if (!section.executable) {
                continue;
            }
            const core::VA start = facts.address_space().to_va(section.rva);
            const core::VA end = start + section.virtual_size;

            for (const auto& gap : out_map.unclaimed_ranges(start, end)) {
                core::VA run_start = core::kInvalidVA;

                for (core::VA va = gap.start; va < gap.end; ++va) {
                    const std::uint8_t* byte = facts.bytes_at(va, 1);
                    const bool padding = (byte != nullptr) && is_padding_byte(*byte);

                    if (padding && run_start == core::kInvalidVA) {
                        run_start = va;
                    } else if (!padding && run_start != core::kInvalidVA) {
                        if (va - run_start >= kMinPaddingRun) {
                            out_map.classify(run_start, va, core::ByteClass::Padding,
                                             core::Confidence::Medium,
                                             core::ProvenanceKind::LinearSweep);
                        }
                        run_start = core::kInvalidVA;
                    }
                }
                if (run_start != core::kInvalidVA && gap.end - run_start >= kMinPaddingRun) {
                    out_map.classify(run_start, gap.end, core::ByteClass::Padding,
                                     core::Confidence::Medium,
                                     core::ProvenanceKind::LinearSweep);
                }
            }
        }
    }

    // --- Pass 3: linear sweep over what is left ---------------------------
    // Finds code reachable only through indirect calls, at the cost of some
    // false positives. Recorded at Low confidence and marked LinearSweep so the
    // UI can shade it and the model can hedge, rather than being silently mixed
    // in with trusted decodes.
    if (options.linear_sweep_fallback) {
        for (const auto& section : facts.address_space().sections()) {
            if (!section.executable) {
                continue;
            }
            const core::VA start = facts.address_space().to_va(section.rva);
            const core::VA end = start + section.virtual_size;

            for (const auto& gap : out_map.unclaimed_ranges(start, end)) {
                core::VA cursor = gap.start;

                while (cursor < gap.end) {
                    if (options.max_instructions != 0
                        && stats_.instructions_decoded >= options.max_instructions) {
                        break;
                    }
                    if (out_instructions.contains(cursor) || out_map.is_claimed(cursor)) {
                        ++cursor;
                        continue;
                    }

                    auto decoded = decode_one(facts, cursor, ids);
                    if (!decoded.ok()) {
                        // Resynchronise one byte at a time: a failure here means
                        // the sweep is misaligned, not that the section ended.
                        ++stats_.decode_failures;
                        ++cursor;
                        continue;
                    }

                    InstructionInfo info = std::move(decoded.value());
                    info.provenance.add({ core::ProvenanceKind::LinearSweep, cursor,
                                          core::Confidence::Low, false });

                    const core::VA next = info.end_address();
                    if (next > gap.end) {
                        // Would overrun into claimed territory; stop here rather
                        // than straddle a boundary.
                        break;
                    }

                    out_map.classify(cursor, next, core::ByteClass::ProbablyCode,
                                     core::Confidence::Low,
                                     core::ProvenanceKind::LinearSweep);

                    out_instructions.add(std::move(info));
                    ++stats_.instructions_decoded;
                    ++stats_.from_linear_sweep;
                    cursor = next;
                }
            }
        }
    }

    // --- Coverage ---------------------------------------------------------
    std::size_t executable_bytes = 0;
    double weighted = 0.0;
    for (const auto& section : facts.address_space().sections()) {
        if (!section.executable) {
            continue;
        }
        const core::VA start = facts.address_space().to_va(section.rva);
        const core::VA end = start + section.virtual_size;
        executable_bytes += section.virtual_size;
        weighted += out_map.code_coverage(start, end) * section.virtual_size;
    }
    stats_.code_coverage = (executable_bytes > 0) ? (weighted / executable_bytes) : 0.0;

    std::ostringstream summary;
    summary << "disassembled " << stats_.instructions_decoded << " instructions"
            << " (descent=" << stats_.from_recursive_descent
            << " sweep=" << stats_.from_linear_sweep
            << " failures=" << stats_.decode_failures
            << ") coverage=" << stats_.code_coverage;
    core::log_info(summary.str());

    return core::Status::success();
}

core::Status Disassembler::retract_range(core::VA start, core::VA end,
                                        core::ProvenanceKind reason,
                                        InstructionStorage& instructions,
                                        CodeMap& map)
{
    // The mechanism behind revisable analysis: withdraw a bad decode instead of
    // living with it. Callers rebuild affected CFGs.
    stats_.retracted += instructions.remove_range(start, end);
    map.reclassify_forced(start, end, core::ByteClass::Data, reason);
    return core::Status::success();
}

} // namespace sp::disasm
