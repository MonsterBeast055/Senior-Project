#pragma once
//
// FactStore.h - Observed, non-negotiable ground truth.
//
// The strict half of the two-tier data model. A fact is something read
// directly out of the file: these bytes exist at this offset, this section has
// these flags, this import table names this symbol. Facts are never mutated by
// analysis and never overwritten by inference.
//
// Everything speculative belongs in AnnotationStore instead. Keeping the two
// apart is what lets us re-run analysis from scratch without losing user work,
// and lets the UI honestly distinguish what is known from what is guessed.
//
#include "sp/core/Types.h"
#include "sp/core/AddressSpace.h"
#include "EntityId.h"

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace sp::db {

struct ImportedSymbol {
    std::string library;
    std::string name;
    std::uint16_t ordinal = 0;
    bool by_ordinal = false;
    core::VA iat_slot = core::kInvalidVA;  // where the resolved pointer lands
};

struct ExportedSymbol {
    std::string name;
    std::uint32_t ordinal = 0;
    core::VA address = core::kInvalidVA;
    bool is_forwarder = false;
    std::string forwarder_target;
};

class FactStore {
public:
    // --- Raw bytes --------------------------------------------------------
    void set_image(std::vector<std::uint8_t> bytes);

    // Read from the mapped image. Returns nullptr if the range is not fully
    // backed by file content.
    const std::uint8_t* bytes_at(core::VA va, std::size_t length) const;

    std::size_t image_size() const { return image_.size(); }

    // --- Address space ----------------------------------------------------
    void set_address_space(core::AddressSpace space);
    const core::AddressSpace& address_space() const { return address_space_; }

    // --- Format-level truth ----------------------------------------------
    void set_arch(core::Arch a) { arch_ = a; }
    core::Arch arch() const { return arch_; }

    void set_entry_point(core::VA va) { entry_point_ = va; }
    core::VA entry_point() const { return entry_point_; }

    void add_import(ImportedSymbol sym);
    void add_export(ExportedSymbol sym);
    void add_tls_callback(core::VA va);

    // Record a function's extent as declared by .pdata. `end` is exclusive.
    void add_unwind_function(core::VA begin, core::VA end);

    const std::vector<ImportedSymbol>& imports() const { return imports_; }
    const std::vector<ExportedSymbol>& exports() const { return exports_; }

    // Function starts recovered from .pdata. On x64 PE this is the single
    // highest-value source of function boundaries available.
    const std::vector<core::VA>& unwind_function_starts() const { return unwind_starts_; }

    // Authoritative function extents from .pdata, keyed by start address.
    //
    // The end address matters as much as the start. Without it a function's
    // extent has to be inferred from where the *next* function begins, which
    // fails completely in a region where discovery found no other functions -
    // the walk then runs on until it happens to hit a return, swallowing
    // everything in between.
    const std::map<core::VA, core::VA>& unwind_function_extents() const
    {
        return unwind_extents_;
    }

    // Declared end of the function starting at `begin`, if .pdata covers it.
    std::optional<core::VA> unwind_extent_of(core::VA begin) const;

    const std::vector<core::VA>& tls_callbacks() const { return tls_callbacks_; }

    // Reverse lookup: which import does this IAT slot correspond to?
    const ImportedSymbol* import_at_iat_slot(core::VA slot) const;

private:
    std::vector<std::uint8_t> image_;
    core::AddressSpace address_space_;
    core::Arch arch_ = core::Arch::Unknown;
    core::VA entry_point_ = core::kInvalidVA;

    std::vector<ImportedSymbol> imports_;
    std::vector<ExportedSymbol> exports_;
    std::vector<core::VA> unwind_starts_;
    std::map<core::VA, core::VA> unwind_extents_;
    std::vector<core::VA> tls_callbacks_;

    std::unordered_map<core::VA, std::size_t> iat_slot_index_;
};

} // namespace sp::db
