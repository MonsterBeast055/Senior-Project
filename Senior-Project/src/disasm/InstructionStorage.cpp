#include "sp/disasm/InstructionStorage.h"

namespace sp::disasm {

void InstructionStorage::add(const InstructionInfo& instruction)
{
    InstructionInfo copy = instruction;
    add(std::move(copy));
}

void InstructionStorage::add(InstructionInfo&& instruction)
{
    const core::VA address = instruction.address;
    const db::EntityId id = instruction.id;

    by_address_[address] = std::move(instruction);
    if (id.valid()) {
        id_index_[id] = address;
    }
}

bool InstructionStorage::contains(core::VA address) const
{
    return by_address_.find(address) != by_address_.end();
}

InstructionInfo* InstructionStorage::get(core::VA address)
{
    auto it = by_address_.find(address);
    return it == by_address_.end() ? nullptr : &it->second;
}

const InstructionInfo* InstructionStorage::get(core::VA address) const
{
    auto it = by_address_.find(address);
    return it == by_address_.end() ? nullptr : &it->second;
}

const InstructionInfo* InstructionStorage::covering(core::VA address) const
{
    // Greatest start address <= address, then check the byte range.
    auto it = by_address_.upper_bound(address);
    if (it == by_address_.begin()) {
        return nullptr;
    }
    --it;
    const InstructionInfo& candidate = it->second;
    if (address >= candidate.address && address < candidate.end_address()) {
        return &candidate;
    }
    return nullptr;
}

InstructionInfo* InstructionStorage::by_id(db::EntityId id)
{
    auto it = id_index_.find(id);
    return it == id_index_.end() ? nullptr : get(it->second);
}

const InstructionInfo* InstructionStorage::by_id(db::EntityId id) const
{
    auto it = id_index_.find(id);
    return it == id_index_.end() ? nullptr : get(it->second);
}

std::size_t InstructionStorage::remove_range(core::VA start, core::VA end)
{
    std::size_t removed = 0;
    auto it = by_address_.lower_bound(start);
    while (it != by_address_.end() && it->first < end) {
        if (it->second.id.valid()) {
            id_index_.erase(it->second.id);
        }
        it = by_address_.erase(it);
        ++removed;
    }
    return removed;
}

std::vector<const InstructionInfo*> InstructionStorage::in_range(core::VA start,
                                                                core::VA end) const
{
    std::vector<const InstructionInfo*> result;
    for (auto it = by_address_.lower_bound(start); it != by_address_.end() && it->first < end; ++it) {
        result.push_back(&it->second);
    }
    return result;
}

void InstructionStorage::clear()
{
    by_address_.clear();
    id_index_.clear();
}

} // namespace sp::disasm
