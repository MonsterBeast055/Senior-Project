#include "sp/core/Types.h"

namespace sp::core {

const char* to_string(Arch arch)
{
    switch (arch) {
    case Arch::X86:    return "x86";
    case Arch::X86_64: return "x86_64";
    case Arch::Unknown:
    default:           return "unknown";
    }
}

unsigned pointer_bits(Arch arch)
{
    switch (arch) {
    case Arch::X86:    return 32;
    case Arch::X86_64: return 64;
    default:           return 0;
    }
}

} // namespace sp::core
