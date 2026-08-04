#include "sp/loader/BinaryLoader.h"

#include "sp/core/Log.h"
#include "sp/loader/PeFormat.h"

#include <algorithm>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

// The only translation unit permitted to include LIEF.
#include <LIEF/PE.hpp>

namespace sp::loader {
namespace {

core::Arch to_arch(LIEF::PE::Header::MACHINE_TYPES machine)
{
    switch (machine) {
    case LIEF::PE::Header::MACHINE_TYPES::AMD64: return core::Arch::X86_64;
    case LIEF::PE::Header::MACHINE_TYPES::I386:  return core::Arch::X86;
    default:                                     return core::Arch::Unknown;
    }
}

std::string hex(std::uint64_t value)
{
    std::ostringstream out;
    out << "0x" << std::hex << value;
    return out.str();
}

core::AddressSpace build_address_space(const LIEF::PE::Binary& binary,
                                       core::VA image_base,
                                       bool compute_entropy)
{
    std::vector<core::SectionRange> ranges;

    for (const auto& section : binary.sections()) {
        core::SectionRange range;
        range.name = section.name();
        range.rva = static_cast<core::RVA>(section.virtual_address());
        range.raw_offset = section.pointerto_raw_data();
        range.raw_size = static_cast<std::uint32_t>(section.sizeof_raw_data());

        // A section may declare no virtual size, in which case the raw size is
        // what gets mapped. Without this fallback such a section is zero-length
        // and every address inside it looks unmapped.
        const auto declared_virtual_size = static_cast<std::uint32_t>(section.virtual_size());
        range.virtual_size = (declared_virtual_size != 0) ? declared_virtual_size
                                                          : range.raw_size;

        range.executable = section.has_characteristic(
            LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE);
        range.readable = section.has_characteristic(
            LIEF::PE::Section::CHARACTERISTICS::MEM_READ);
        range.writable = section.has_characteristic(
            LIEF::PE::Section::CHARACTERISTICS::MEM_WRITE);

        if (compute_entropy) {
            range.entropy = section.entropy();
        }

        ranges.push_back(std::move(range));
    }

    return core::AddressSpace(image_base, std::move(ranges));
}

void load_imports(const LIEF::PE::Binary& binary, core::VA image_base, db::FactStore& out)
{
    for (const auto& library : binary.imports()) {
        for (const auto& entry : library.entries()) {
            db::ImportedSymbol symbol;
            symbol.library = library.name();
            symbol.by_ordinal = entry.is_ordinal();

            if (symbol.by_ordinal) {
                symbol.ordinal = entry.ordinal();
            } else {
                symbol.name = entry.name();
            }

            // The IAT slot is what an indirect call actually reads, so this is
            // the address SymbolTable needs to turn "call qword [rip+0x1234]"
            // into "call kernel32!CreateFileW".
            const std::uint64_t iat_rva = entry.iat_address();
            symbol.iat_slot = (iat_rva != 0) ? (image_base + iat_rva) : core::kInvalidVA;

            out.add_import(std::move(symbol));
        }
    }
}

void load_exports(const LIEF::PE::Binary& binary, core::VA image_base, db::FactStore& out)
{
    const LIEF::PE::Export* table = binary.get_export();
    if (table == nullptr) {
        return;
    }

    for (const auto& entry : table->entries()) {
        db::ExportedSymbol symbol;
        symbol.name = entry.name();
        symbol.ordinal = entry.ordinal();
        symbol.is_forwarder = entry.is_forwarded();

        if (symbol.is_forwarder) {
            // A forwarder has no code here; it names a symbol in another DLL.
            symbol.address = core::kInvalidVA;
        } else {
            const std::uint64_t rva = entry.address();
            symbol.address = (rva != 0) ? (image_base + rva) : core::kInvalidVA;
        }

        out.add_export(std::move(symbol));
    }
}

// Read the exception directory and record every function start it declares.
//
// On x64 PE this is the strongest boundary evidence available: the linker
// emitted one RUNTIME_FUNCTION per function with a real prologue. Parsed from
// raw bytes via PeFormat rather than LIEF's exception API, which has changed
// shape between releases.
std::size_t load_unwind_starts(const LIEF::PE::Binary& binary,
                              core::VA image_base,
                              const std::vector<std::uint8_t>& image,
                              const core::AddressSpace& space,
                              db::FactStore& out)
{
    const LIEF::PE::DataDirectory* directory = binary.exceptions_dir();

    if (directory == nullptr || directory->RVA() == 0 || directory->size() == 0) {
        return 0;
    }

    // Prefer LIEF's own view of the directory contents: it has already resolved
    // which section backs this RVA, so we are not relying on our address
    // translation being right for this one lookup.
    //
    // Note we do NOT use binary.exceptions(), which needs
    // ParserConfig::parse_exceptions (off by default) and whose shape has
    // changed across LIEF releases. The on-disk RUNTIME_FUNCTION layout is
    // fixed, so parsing it directly is version-proof.
    std::vector<RuntimeFunction> functions;

    if (auto content = directory->content(); !content.empty()) {
        functions = parse_unwind_table(content.data(), content.size());
    } else {
        // Fall back to our own RVA -> file offset mapping.
        const core::VA table_va = image_base + directory->RVA();
        const auto offset = space.to_file_offset(table_va);
        if (!offset.has_value() || *offset >= image.size()) {
            core::log_warn("exception directory RVA " + hex(directory->RVA())
                           + " is not backed by file content; skipping unwind info");
            return 0;
        }

        // Clamp to what the file actually contains: a declared size larger than
        // the remaining bytes is either corruption or a deliberate lie.
        const std::size_t available = image.size() - static_cast<std::size_t>(*offset);
        const std::size_t length =
            std::min<std::size_t>(static_cast<std::size_t>(directory->size()), available);

        functions = parse_unwind_table(image.data() + *offset, length);
    }

    // Keep the end address, not just the start. It is an authoritative
    // statement of where the function stops, and it is the only boundary source
    // that still works in a region where nothing else was discovered.
    for (const RuntimeFunction& function : functions) {
        out.add_unwind_function(image_base + function.begin_rva,
                                image_base + function.end_rva);
    }
    return functions.size();
}

void load_tls_callbacks(const LIEF::PE::Binary& binary, db::FactStore& out)
{
    const LIEF::PE::TLS* tls = binary.tls();
    if (tls == nullptr) {
        return;
    }
    // Callbacks are stored as absolute virtual addresses, not RVAs.
    for (std::uint64_t callback : tls->callbacks()) {
        if (callback != 0) {
            out.add_tls_callback(callback);
        }
    }
}

} // namespace

bool BinaryLoader::is_pe(const std::string& path)
{
    std::vector<std::uint8_t> bytes;
    if (!read_file(path, bytes)) {
        return false;
    }
    return has_pe_signature(bytes.data(), bytes.size());
}

core::Status BinaryLoader::load_pe(const std::string& path,
                                  const LoadOptions& options,
                                  db::FactStore& out)
{
    // Read the file ourselves rather than relying on LIEF's view of it: the
    // disassembler needs raw bytes at true file offsets, and this is also the
    // cheapest way to reject non-PE input before paying for a full parse.
    std::vector<std::uint8_t> image;
    if (!read_file(path, image)) {
        return core::Error(core::ErrorCode::FileNotFound, "cannot open file: " + path);
    }

    if (!has_pe_signature(image.data(), image.size())) {
        return core::Error(core::ErrorCode::NotAPeFile,
                           "missing MZ/PE signature: " + path);
    }

    std::unique_ptr<LIEF::PE::Binary> binary = LIEF::PE::Parser::parse(path);
    if (binary == nullptr) {
        return core::Error(core::ErrorCode::NotAPeFile, "LIEF failed to parse: " + path);
    }

    const core::Arch arch = to_arch(binary->header().machine());
    if (arch == core::Arch::Unknown) {
        return core::Error(core::ErrorCode::UnsupportedArchitecture,
                           std::string("unsupported machine type: ")
                               + LIEF::PE::to_string(binary->header().machine()));
    }

    const core::VA image_base = binary->optional_header().imagebase();

    // Everything that can fail has now been checked, so it is safe to start
    // writing into `out` - the contract says it stays untouched on failure.
    core::AddressSpace space = build_address_space(*binary, image_base, options.compute_entropy);

    out.set_arch(arch);
    out.set_address_space(space);

    const std::uint64_t entry_rva = binary->optional_header().addressof_entrypoint();
    out.set_entry_point(entry_rva != 0 ? (image_base + entry_rva) : core::kInvalidVA);

    std::size_t unwind_count = 0;
    if (options.parse_unwind_info) {
        unwind_count = load_unwind_starts(*binary, image_base, image, space, out);
    }
    if (options.parse_imports) {
        load_imports(*binary, image_base, out);
    }
    if (options.parse_exports) {
        load_exports(*binary, image_base, out);
    }
    if (options.parse_tls) {
        load_tls_callbacks(*binary, out);
    }

    // Moved last: everything above reads from the local copy.
    out.set_image(std::move(image));

    std::ostringstream summary;
    summary << "loaded " << path
            << " arch=" << core::to_string(arch)
            << " base=" << hex(image_base)
            << " entry=" << hex(out.entry_point())
            << " sections=" << out.address_space().sections().size()
            << " imports=" << out.imports().size()
            << " exports=" << out.exports().size()
            << " unwind_starts=" << unwind_count
            << " tls_callbacks=" << out.tls_callbacks().size();
    core::log_info(summary.str());

    if (unwind_count == 0 && arch == core::Arch::X86_64) {
        // Worth flagging loudly. On x64 an absent .pdata table means we have
        // lost our best source of function boundaries and will be leaning on
        // call targets and prologue heuristics instead.
        core::log_warn("no unwind info found; function discovery will be weaker");
    }

    return core::Status::success();
}

} // namespace sp::loader
