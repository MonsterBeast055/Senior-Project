#include <iostream>
#include <vector>
#include <set>
#include <unordered_map>
#include <optional>
#include <fstream>
#include <sstream>
#include <memory>
#include <LIEF/PE.hpp>
#include "Senior-Project.h"
#include <capstone/capstone.h>
using namespace std;


int main()
{
    auto binary = LIEF::PE::Parser::parse("C:\\Windows\\System32\\notepad.exe");

    if (!binary) {
        std::cout << "Failed to parse PE file\n";
        return 1;
    }

    std::cout << "PE parsed successfully\n\n";

    const auto& dos_header = binary->dos_header();
    const auto& header = binary->header();
    const auto& optional_header = binary->optional_header();

    std::cout << "=== DOS HEADER ===\n";
    std::cout << "PE Header offset: 0x"
        << std::hex
        << dos_header.addressof_new_exeheader()
        << "\n\n";

    std::cout << "=== PE HEADER ===\n";
    auto machine = header.machine();
    auto noOfSections = header.numberof_sections();

    std::cout << "Machine: " << LIEF::PE::to_string(machine) << "\n";
    std::cout << "Number of Sections: " << std::dec << noOfSections << "\n\n";

    std::cout << "=== OPTIONAL HEADER ===\n";
    uint64_t image_base = optional_header.imagebase();
    uint64_t entry_rva = optional_header.addressof_entrypoint();
    uint64_t entry_va = image_base + entry_rva;

    std::cout << "Image Base: 0x" << std::hex << image_base << "\n";
    std::cout << "Entry Point RVA: 0x" << entry_rva << "\n";
    std::cout << "Entry Point VA: 0x" << entry_va << "\n\n";

    std::cout << "=== SECTIONS ===\n";

    for (const auto& section : binary->sections()) {
        uint64_t section_rva = section.virtual_address();
        uint64_t section_va = image_base + section_rva;
        auto bytes = section.content();

        std::cout << "Section: " << section.name() << "\n";
        std::cout << "  RVA: 0x" << std::hex << section_rva << "\n";
        std::cout << "  VA:  0x" << section_va << "\n";
        std::cout << "  Bytes size: " << std::dec << bytes.size() << "\n";
        std::cout << "  Entropy: " << section.entropy() << "\n\n";
    }

    std::cout << "=== .TEXT SECTION ===\n";

    const LIEF::PE::Section* text = binary->get_section(".text");

    if (!text) {
        std::cout << ".text section not found\n";
        return 1;
    }

    auto code_bytes = text->content();
    uint64_t code_va = image_base + text->virtual_address();

    std::cout << ".text VA: 0x" << std::hex << code_va << "\n";
    std::cout << ".text bytes: " << std::dec << code_bytes.size() << "\n\n";


    std::cout << "=== IMPORTS ===\n";

    for (const auto& imported_lib : binary->imports()) {
        std::cout << "DLL: " << imported_lib.name() << "\n";

        for (const auto& entry : imported_lib.entries()) {
            std::cout << "  - " << entry.name() << "\n";
        }

        std::cout << "\n";
    }

    cs_mode mode;

    if (header.machine() == LIEF::PE::Header::MACHINE_TYPES::AMD64) {
        mode = CS_MODE_64;
        std::cout << "Architecture: x64\n\n";
    }
    else if (header.machine() == LIEF::PE::Header::MACHINE_TYPES::I386) {
        mode = CS_MODE_32;
        std::cout << "Architecture: x86\n\n";
    }
    else {
        std::cout << "Unsupported Architecture for Capstone\n";
    }

    if (!cs_support(CS_ARCH_X86)) {
        std::cout << "This capstone build does not support X86 architecture\n";
        return 1;
    }

    // Open Capstone Engine
    csh handle;

    if (cs_open(CS_ARCH_X86, mode, &handle) != CS_ERR_OK) {
        std::cout << "Failed to open capstone engine\n";
        return 1;
    }

    // Disassemble .text bytes
    cs_insn* instructions = nullptr;

    size_t count = cs_disasm(
        handle,
        code_bytes.data(),
        code_bytes.size(),
        code_va,
        50,
        &instructions
        );

    if (count == 0) {
        std::cout << "Capstone could not disassemble the .text section\n";
        cs_close(&handle);
        return 1;
    }

    std::cout << "=== DISASSEMBLY: first 50 instructions ===\n";

    for (size_t i = 0; i < count; i++) {
        std::cout << "0x"
            << std::hex
            << instructions[i].address
            << ":\t"
            << instructions[i].mnemonic
            << "\t"
            << instructions[i].op_str
            << "\n";
    }

    // CLEANUP
    cs_free(instructions, count);
    cs_close(&handle);

    return 0;
}