#pragma once
//
// XrefTable.h - Bidirectional cross-references.
//
// "What refers to this address?" is the most-used query in any reverse
// engineering workflow, and it is equally what the model needs to establish how
// a function is used before guessing what it does.
//
#include "sp/core/Types.h"
#include "sp/core/Confidence.h"
#include "sp/db/EntityId.h"

#include <unordered_map>
#include <vector>

namespace sp::analysis {

enum class XrefType : std::uint8_t {
    Call = 0,
    Jump,
    Read,          // data read
    Write,         // data write
    AddressTaken,  // address loaded as a value (lea, immediate pointer)
    StringRef,
};

const char* to_string(XrefType t);

struct Xref {
    core::VA from = core::kInvalidVA;
    core::VA to = core::kInvalidVA;
    XrefType type = XrefType::Call;
    core::Confidence confidence = core::Confidence::None;
};

class XrefTable {
public:
    void add(Xref xref);

    // Everything that references `va`. The reverse query.
    const std::vector<Xref>* references_to(core::VA va) const;

    // Everything `va` references. The forward query.
    const std::vector<Xref>* references_from(core::VA va) const;

    std::vector<Xref> references_to_of_type(core::VA va, XrefType type) const;

    std::size_t reference_count_to(core::VA va) const;

    void clear();

private:
    std::unordered_map<core::VA, std::vector<Xref>> to_index_;
    std::unordered_map<core::VA, std::vector<Xref>> from_index_;
};
} // namespace sp::analysis
