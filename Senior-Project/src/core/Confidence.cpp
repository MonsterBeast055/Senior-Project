#include "sp/core/Confidence.h"

namespace sp::core {

const char* to_string(Confidence c)
{
    switch (c) {
    case Confidence::None:    return "none";
    case Confidence::Low:     return "low";
    case Confidence::Medium:  return "medium";
    case Confidence::High:    return "high";
    case Confidence::Certain: return "certain";
    default:                  return "?";
    }
}

const char* to_string(ByteClass bc)
{
    switch (bc) {
    case ByteClass::Unknown:       return "unknown";
    case ByteClass::ProbablyData:  return "probably-data";
    case ByteClass::ProbablyCode:  return "probably-code";
    case ByteClass::Code:          return "code";
    case ByteClass::Data:          return "data";
    case ByteClass::Padding:       return "padding";
    default:                       return "?";
    }
}

} // namespace sp::core
