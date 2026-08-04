#include "sp/core/AddressSpace.h"

#include <algorithm>

namespace sp::core {

AddressSpace::AddressSpace(VA image_base, std::vector<SectionRange> sections)
    : image_base_(image_base), sections_(std::move(sections))
{
    std::sort(sections_.begin(), sections_.end(),
              [](const SectionRange& a, const SectionRange& b) { return a.rva < b.rva; });
}

std::optional<RVA> AddressSpace::to_rva(VA va) const
{
    if (va < image_base_) {
        return std::nullopt;
    }
    const std::uint64_t delta = va - image_base_;
    if (delta > 0xFFFFFFFFull) {
        return std::nullopt;
    }
    return static_cast<RVA>(delta);
}

std::optional<FileOffset> AddressSpace::to_file_offset(VA va) const
{
    const SectionRange* section = section_containing(va);
    if (section == nullptr) {
        return std::nullopt;
    }

    const RVA rva = static_cast<RVA>(va - image_base_);
    const std::uint32_t offset_in_section = rva - section->rva;

    // Virtual size can exceed raw size; the tail has no bytes on disk.
    if (offset_in_section >= section->raw_size) {
        return std::nullopt;
    }
    return section->raw_offset + offset_in_section;
}

const SectionRange* AddressSpace::section_containing(VA va) const
{
    auto rva = to_rva(va);
    if (!rva.has_value()) {
        return nullptr;
    }
    for (const auto& section : sections_) {
        if (*rva >= section.rva && *rva < section.rva + section.virtual_size) {
            return &section;
        }
    }
    return nullptr;
}

const SectionRange* AddressSpace::section_by_name(const std::string& name) const
{
    for (const auto& section : sections_) {
        if (section.name == name) {
            return &section;
        }
    }
    return nullptr;
}

bool AddressSpace::is_mapped(VA va) const
{
    return section_containing(va) != nullptr;
}

bool AddressSpace::is_executable(VA va) const
{
    const SectionRange* section = section_containing(va);
    return section != nullptr && section->executable;
}

} // namespace sp::core
