#pragma once
//
// SymbolTable.h - Address to meaningful name.
//
// "call 0x140001a20" is close to useless; "call CreateFileW" is most of the
// answer. Resolves addresses through exports, the import address table, thunk
// following, and generated fallback names.
//
// Reads display names from the AnnotationStore, so a name supplied by a user or
// accepted from the model automatically takes effect everywhere.
//
#include "sp/core/Types.h"
#include "sp/db/AnnotationStore.h"
#include "sp/db/FactStore.h"
#include "sp/db/EntityId.h"

#include <optional>
#include <string>
#include <unordered_map>

namespace sp::analysis {

enum class SymbolSource : std::uint8_t {
    Generated = 0,   // sub_140001a20
    Export,
    Import,
    ImportThunk,     // local stub jumping to an import
    DebugInfo,
    Annotation,      // user or accepted AI name
};

const char* to_string(SymbolSource s);

struct Symbol {
    std::string name;
    core::VA address = core::kInvalidVA;
    SymbolSource source = SymbolSource::Generated;

    // Set for imports: the owning DLL.
    std::string module;

    bool is_function = false;
};

class SymbolTable {
public:
    // Seed from format-level facts (exports, imports, IAT slots).
    void build(const db::FactStore& facts);

    void add(Symbol symbol);

    const Symbol* lookup(core::VA address) const;

    // Name for display, checking the annotation store first and falling back to
    // a generated name. Always returns something usable.
    std::string name_for(core::VA address,
                         const db::AnnotationStore* annotations = nullptr,
                         db::EntityId entity = db::kNoEntity) const;

    // Resolve an indirect call through an IAT slot to the imported symbol.
    const Symbol* resolve_iat_slot(core::VA slot) const;

    std::optional<core::VA> address_of(const std::string& name) const;

    static std::string generated_name(core::VA address, bool is_function);

private:
    std::unordered_map<core::VA, Symbol> by_address_;
    std::unordered_map<std::string, core::VA> by_name_;
};

} // namespace sp::analysis
