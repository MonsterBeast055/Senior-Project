#pragma once
//
// InstructionStorage.h - Address-indexed instruction container.
//
// Stores decoded instructions and supports lookup by exact address, lookup of
// the instruction covering an address (needed when a branch lands mid-
// instruction, which is a strong obfuscation signal), and retraction of a
// range when a pass proves it was misdecoded.
//
#include "InstructionInfo.h"
#include "sp/core/Types.h"
#include "sp/db/EntityId.h"

#include <cstddef>
#include <map>
#include <unordered_map>
#include <vector>

namespace sp::disasm {

class InstructionStorage {
public:
    // Insert or replace the instruction at `instruction.address`.
    void add(const InstructionInfo& instruction);
    void add(InstructionInfo&& instruction);

    bool contains(core::VA address) const;

    InstructionInfo* get(core::VA address);
    const InstructionInfo* get(core::VA address) const;

    // The instruction whose byte range covers `address`, even if `address` is
    // not its start. Detects overlapping / misaligned decodes.
    const InstructionInfo* covering(core::VA address) const;

    InstructionInfo* by_id(db::EntityId id);
    const InstructionInfo* by_id(db::EntityId id) const;

    // Remove instructions in [start, end). Used when a region is reclassified
    // as data, so bad decodes do not linger in the output.
    std::size_t remove_range(core::VA start, core::VA end);

    // Instructions in ascending address order within [start, end).
    std::vector<const InstructionInfo*> in_range(core::VA start, core::VA end) const;

    // Iteration in address order.
    using const_iterator = std::map<core::VA, InstructionInfo>::const_iterator;
    const_iterator begin() const { return by_address_.begin(); }
    const_iterator end() const { return by_address_.end(); }

    std::size_t size() const { return by_address_.size(); }
    bool empty() const { return by_address_.empty(); }
    void clear();

private:
    // Ordered by address: enables covering() and in_range() without a scan.
    std::map<core::VA, InstructionInfo> by_address_;
    std::unordered_map<db::EntityId, core::VA> id_index_;
};

} // namespace sp::disasm
