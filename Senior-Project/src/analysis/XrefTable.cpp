#include "sp/analysis/XrefTable.h"

namespace sp::analysis {

const char* to_string(XrefType t)
{
    switch (t) {
    case XrefType::Call:         return "call";
    case XrefType::Jump:         return "jump";
    case XrefType::Read:         return "read";
    case XrefType::Write:        return "write";
    case XrefType::AddressTaken: return "address-taken";
    case XrefType::StringRef:    return "string-ref";
    default:                     return "?";
    }
}

void XrefTable::add(Xref xref)
{
    to_index_[xref.to].push_back(xref);
    from_index_[xref.from].push_back(xref);
}

const std::vector<Xref>* XrefTable::references_to(core::VA va) const
{
    auto it = to_index_.find(va);
    return it == to_index_.end() ? nullptr : &it->second;
}

const std::vector<Xref>* XrefTable::references_from(core::VA va) const
{
    auto it = from_index_.find(va);
    return it == from_index_.end() ? nullptr : &it->second;
}

std::vector<Xref> XrefTable::references_to_of_type(core::VA va, XrefType type) const
{
    std::vector<Xref> result;
    const std::vector<Xref>* all = references_to(va);
    if (all == nullptr) {
        return result;
    }
    for (const Xref& xref : *all) {
        if (xref.type == type) {
            result.push_back(xref);
        }
    }
    return result;
}

std::size_t XrefTable::reference_count_to(core::VA va) const
{
    const std::vector<Xref>* all = references_to(va);
    return all == nullptr ? 0 : all->size();
}

void XrefTable::clear()
{
    to_index_.clear();
    from_index_.clear();
}

} // namespace sp::analysis
