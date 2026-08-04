#include "sp/disasm/DecodeQueue.h"

namespace sp::disasm {

void DecodeQueue::push(DecodeRequest request)
{
    if (request.address == core::kInvalidVA) {
        return;
    }
    if (seen_.find(request.address) != seen_.end()) {
        return;
    }
    if (request.priority == core::Confidence::None) {
        request.priority = core::base_confidence(request.reason);
    }
    seen_.insert(request.address);
    queue_.push(request);
}

bool DecodeQueue::pop(DecodeRequest& out)
{
    if (queue_.empty()) {
        return false;
    }
    out = queue_.top();
    queue_.pop();
    return true;
}

bool DecodeQueue::empty() const
{
    return queue_.empty();
}

std::size_t DecodeQueue::pending() const
{
    return queue_.size();
}

bool DecodeQueue::seen(core::VA address) const
{
    return seen_.find(address) != seen_.end();
}

void DecodeQueue::forget(core::VA address)
{
    seen_.erase(address);
}

void DecodeQueue::clear()
{
    while (!queue_.empty()) {
        queue_.pop();
    }
    seen_.clear();
}

} // namespace sp::disasm
