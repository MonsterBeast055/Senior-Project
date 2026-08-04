#include "sp/disasm/InstructionInfo.h"

namespace sp::disasm {

const char* to_string(FlowKind k)
{
    switch (k) {
    case FlowKind::Sequential:        return "sequential";
    case FlowKind::ConditionalJump:   return "conditional-jump";
    case FlowKind::UnconditionalJump: return "unconditional-jump";
    case FlowKind::Call:              return "call";
    case FlowKind::Return:            return "return";
    case FlowKind::Interrupt:         return "interrupt";
    case FlowKind::Halt:              return "halt";
    case FlowKind::Unknown:
    default:                          return "unknown";
    }
}

} // namespace sp::disasm
