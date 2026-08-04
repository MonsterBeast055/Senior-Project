#include "sp/db/FactStore.h"

namespace sp::db {

void FactStore::set_image(std::vector<std::uint8_t> bytes)
{
    image_ = std::move(bytes);
}

const std::uint8_t* FactStore::bytes_at(core::VA va, std::size_t length) const
{
    auto offset = address_space_.to_file_offset(va);
    if (!offset.has_value()) {
        return nullptr;
    }
    if (*offset + length > image_.size()) {
        return nullptr;
    }
    return image_.data() + *offset;
}

void FactStore::set_address_space(core::AddressSpace space)
{
    address_space_ = std::move(space);
}

void FactStore::add_import(ImportedSymbol sym)
{
    if (sym.iat_slot != core::kInvalidVA) {
        iat_slot_index_[sym.iat_slot] = imports_.size();
    }
    imports_.push_back(std::move(sym));
}

void FactStore::add_export(ExportedSymbol sym)
{
    exports_.push_back(std::move(sym));
}

void FactStore::add_unwind_function(core::VA begin, core::VA end)
{
    unwind_starts_.push_back(begin);
    if (end > begin) {
        unwind_extents_[begin] = end;
    }
}

std::optional<core::VA> FactStore::unwind_extent_of(core::VA begin) const
{
    auto it = unwind_extents_.find(begin);
    if (it == unwind_extents_.end()) {
        return std::nullopt;
    }
    return it->second;
}

void FactStore::add_tls_callback(core::VA va)
{
    tls_callbacks_.push_back(va);
}

const ImportedSymbol* FactStore::import_at_iat_slot(core::VA slot) const
{
    auto it = iat_slot_index_.find(slot);
    if (it == iat_slot_index_.end()) {
        return nullptr;
    }
    return &imports_[it->second];
}

} // namespace sp::db
