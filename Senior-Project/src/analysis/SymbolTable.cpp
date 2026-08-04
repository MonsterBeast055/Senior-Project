#include "sp/analysis/SymbolTable.h"

#include <sstream>

namespace sp::analysis {

const char* to_string(SymbolSource s)
{
    switch (s) {
    case SymbolSource::Generated:   return "generated";
    case SymbolSource::Export:      return "export";
    case SymbolSource::Import:      return "import";
    case SymbolSource::ImportThunk: return "import-thunk";
    case SymbolSource::DebugInfo:   return "debug-info";
    case SymbolSource::Annotation:  return "annotation";
    default:                        return "?";
    }
}

std::string SymbolTable::generated_name(core::VA address, bool is_function)
{
    std::ostringstream out;
    out << (is_function ? "sub_" : "data_") << std::hex << address;
    return out.str();
}

void SymbolTable::add(Symbol symbol)
{
    by_name_[symbol.name] = symbol.address;
    by_address_[symbol.address] = std::move(symbol);
}

void SymbolTable::build(const db::FactStore& facts)
{
    by_address_.clear();
    by_name_.clear();

    for (const auto& sym : facts.exports()) {
        Symbol symbol;
        symbol.name = sym.name;
        symbol.address = sym.address;
        symbol.source = SymbolSource::Export;
        symbol.is_function = true;
        add(std::move(symbol));
    }

    // Imports are keyed by their IAT slot, not by a code address: an indirect
    // call reads the slot, so resolving the slot is what turns
    // "call qword [rip+0x1234]" into "call kernel32!CreateFileW".
    for (const auto& sym : facts.imports()) {
        Symbol symbol;
        symbol.name = sym.name.empty()
            ? (sym.library + "!ordinal_" + std::to_string(sym.ordinal))
            : (sym.library + "!" + sym.name);
        symbol.address = sym.iat_slot;
        symbol.module = sym.library;
        symbol.source = SymbolSource::Import;
        symbol.is_function = true;
        add(std::move(symbol));
    }
}

const Symbol* SymbolTable::lookup(core::VA address) const
{
    auto it = by_address_.find(address);
    return it == by_address_.end() ? nullptr : &it->second;
}

const Symbol* SymbolTable::resolve_iat_slot(core::VA slot) const
{
    const Symbol* symbol = lookup(slot);
    if (symbol != nullptr && symbol->source == SymbolSource::Import) {
        return symbol;
    }
    return nullptr;
}

std::string SymbolTable::name_for(core::VA address,
                                 const db::AnnotationStore* annotations,
                                 db::EntityId entity) const
{
    // A name supplied by a user, or accepted from the model, outranks anything
    // derived. This is the single place that precedence is decided, so it holds
    // everywhere in the UI and in the model's context.
    if (annotations != nullptr && entity.valid()) {
        auto annotated = annotations->display_name(entity);
        if (annotated.has_value()) {
            return *annotated;
        }
    }
    const Symbol* symbol = lookup(address);
    if (symbol != nullptr) {
        return symbol->name;
    }
    return generated_name(address, true);
}

std::optional<core::VA> SymbolTable::address_of(const std::string& name) const
{
    auto it = by_name_.find(name);
    if (it == by_name_.end()) {
        return std::nullopt;
    }
    return it->second;
}

} // namespace sp::analysis
