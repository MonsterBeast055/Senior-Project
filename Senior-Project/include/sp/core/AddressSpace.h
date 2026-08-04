#pragma once
//
// AddressSpace.h - Authoritative address translation.
//
// Owns the mapping between virtual addresses, RVAs and file offsets, and
// answers "which section contains this address". Every other module asks this
// class rather than doing its own arithmetic.
//
#include "Types.h"
#include "Error.h"

#include <optional>
#include <string>
#include <vector>

namespace sp::core {

struct SectionRange {
    std::string name;
    RVA rva = 0;
    std::uint32_t virtual_size = 0;
    FileOffset raw_offset = 0;
    std::uint32_t raw_size = 0;

    bool executable = false;
    bool writable = false;
    bool readable = false;

    double entropy = 0.0;
};

class AddressSpace {
public:
    AddressSpace() = default;
    AddressSpace(VA image_base, std::vector<SectionRange> sections);

    VA image_base() const { return image_base_; }

    VA to_va(RVA rva) const { return image_base_ + rva; }
    std::optional<RVA> to_rva(VA va) const;

    // Null when the address falls in a region with no backing bytes on disk
    // (e.g. .bss-style virtual-only space).
    std::optional<FileOffset> to_file_offset(VA va) const;

    const SectionRange* section_containing(VA va) const;
    const SectionRange* section_by_name(const std::string& name) const;

    bool is_mapped(VA va) const;
    bool is_executable(VA va) const;

    const std::vector<SectionRange>& sections() const { return sections_; }

private:
    VA image_base_ = 0;
    std::vector<SectionRange> sections_;
};

} // namespace sp::core
