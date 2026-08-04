#include "sp/analysis/BasicBlock.h"

namespace sp::analysis {

const char* to_string(EdgeKind k)
{
    switch (k) {
    case EdgeKind::FallThrough:  return "fall-through";
    case EdgeKind::Taken:        return "taken";
    case EdgeKind::Jump:         return "jump";
    case EdgeKind::IndirectJump: return "indirect-jump";
    case EdgeKind::Call:         return "call";
    case EdgeKind::Return:       return "return";
    default:                     return "?";
    }
}

} // namespace sp::analysis
