#pragma once
//
// BinaryLoader.h - The only module that knows about LIEF.
//
// Parses a PE file and populates a FactStore. Nothing downstream includes a
// LIEF header, which keeps the format dependency swappable and means ELF or
// Mach-O support later means adding a loader, not editing the analysis layer.
//
#include "sp/core/Error.h"
#include "sp/core/Types.h"
#include "sp/db/FactStore.h"

#include <memory>
#include <string>

namespace sp::loader {

struct LoadOptions {
    // Parse the .pdata exception directory for function starts. Cheap, and the
    // best boundary source on x64.
    bool parse_unwind_info = true;

    bool parse_imports = true;
    bool parse_exports = true;
    bool parse_relocations = true;
    bool parse_tls = true;

    // Compute per-section Shannon entropy. Useful for flagging packed or
    // encrypted regions before wasting time disassembling them.
    bool compute_entropy = true;
};

class BinaryLoader {
public:
    // Parse the file at `path` and fill `out`. On failure `out` is untouched.
    static core::Status load_pe(const std::string& path,
                               const LoadOptions& options,
                               db::FactStore& out);

    // True if the file looks like a PE image, without fully parsing it.
    static bool is_pe(const std::string& path);
};

} // namespace sp::loader
