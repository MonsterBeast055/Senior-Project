#pragma once
//
// EntityId.h - Stable identity independent of address.
//
// Names, types and comments produced by a human or by the model must survive
// re-analysis. If they are keyed by address they are lost the moment a pass
// re-splits a basic block or shifts a function start. So every addressable
// analysis object gets an opaque id that is allocated once and never reused,
// and annotations reference the id rather than the address.
//
#include "sp/core/Types.h"

#include <cstdint>
#include <functional>

namespace sp::db {

enum class EntityKind : std::uint8_t {
    Invalid = 0,
    Instruction,
    BasicBlock,
    Function,
    DataObject,
    Section,
    Import,
    Export,
};

struct EntityId {
    std::uint64_t raw = 0;

    bool valid() const { return raw != 0; }

    EntityKind kind() const
    {
        return static_cast<EntityKind>(raw >> 56);
    }

    std::uint64_t index() const { return raw & 0x00FFFFFFFFFFFFFFull; }

    static EntityId make(EntityKind k, std::uint64_t index)
    {
        return EntityId{ (static_cast<std::uint64_t>(k) << 56) | (index & 0x00FFFFFFFFFFFFFFull) };
    }

    friend bool operator==(EntityId a, EntityId b) { return a.raw == b.raw; }
    friend bool operator!=(EntityId a, EntityId b) { return a.raw != b.raw; }
    friend bool operator<(EntityId a, EntityId b) { return a.raw < b.raw; }
};

inline constexpr EntityId kNoEntity{ 0 };

// Monotonic allocator. Ids are never recycled, so a stale reference is always
// detectably stale rather than silently pointing at a different object.
class EntityIdAllocator {
public:
    EntityId allocate(EntityKind kind);

private:
    std::uint64_t next_index_[16] = {};
};

} // namespace sp::db

namespace std {
template <>
struct hash<sp::db::EntityId> {
    size_t operator()(sp::db::EntityId id) const noexcept
    {
        return std::hash<std::uint64_t>{}(id.raw);
    }
};
} // namespace std
