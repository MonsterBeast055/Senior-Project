#include "sp/analysis/Function.h"

namespace sp::analysis {

const char* to_string(CallingConvention c)
{
    switch (c) {
    case CallingConvention::Cdecl:    return "cdecl";
    case CallingConvention::Stdcall:  return "stdcall";
    case CallingConvention::Fastcall: return "fastcall";
    case CallingConvention::Thiscall: return "thiscall";
    case CallingConvention::Win64:    return "win64";
    case CallingConvention::SysV64:   return "sysv64";
    case CallingConvention::Unknown:
    default:                          return "unknown";
    }
}

} // namespace sp::analysis
