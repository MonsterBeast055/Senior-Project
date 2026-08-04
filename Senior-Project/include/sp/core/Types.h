#pragma once
//
// Types.h - Fundamental value types shared across every layer.
//
// Address discipline is enforced through distinct type aliases. Mixing RVAs,
// virtual addresses and file offsets is the single most common source of bugs
// in binary analysis code, so every API in this project states which one it
// expects.
//
#include <cstdint>
#include <string>

namespace sp::core {

// Virtual address: image_base + rva. What the CPU sees at runtime.
using VA = std::uint64_t;

// Relative virtual address: offset from image base.
using RVA = std::uint32_t;

// Raw offset into the file on disk.
using FileOffset = std::uint64_t;

inline constexpr VA kInvalidVA = static_cast<VA>(-1);

enum class Arch : std::uint8_t {
    Unknown = 0,
    X86,      // 32-bit
    X86_64,   // 64-bit
};

const char* to_string(Arch arch);

// Bit width of the architecture's pointer, or 0 if unknown.
unsigned pointer_bits(Arch arch);

} // namespace sp::core
