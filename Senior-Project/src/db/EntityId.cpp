#include "sp/db/EntityId.h"

namespace sp::db {

EntityId EntityIdAllocator::allocate(EntityKind kind)
{
    const auto slot = static_cast<std::size_t>(kind) & 0xF;
    return EntityId::make(kind, ++next_index_[slot]);
}

} // namespace sp::db
