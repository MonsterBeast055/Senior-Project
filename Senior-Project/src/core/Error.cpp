#include "sp/core/Error.h"

namespace sp::core {

const char* to_string(ErrorCode c)
{
    switch (c) {
    case ErrorCode::Ok:                      return "ok";
    case ErrorCode::FileNotFound:            return "file-not-found";
    case ErrorCode::NotAPeFile:              return "not-a-pe-file";
    case ErrorCode::UnsupportedArchitecture: return "unsupported-architecture";
    case ErrorCode::SectionNotFound:         return "section-not-found";
    case ErrorCode::DisassemblerInitFailed:  return "disassembler-init-failed";
    case ErrorCode::DecodeFailed:            return "decode-failed";
    case ErrorCode::InvalidAddress:          return "invalid-address";
    case ErrorCode::InvalidArgument:         return "invalid-argument";
    case ErrorCode::Internal:
    default:                                 return "internal";
    }
}

} // namespace sp::core
