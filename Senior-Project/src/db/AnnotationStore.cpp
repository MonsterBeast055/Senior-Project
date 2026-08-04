#include "sp/db/AnnotationStore.h"

namespace sp::db {

const char* to_string(AnnotationOrigin o)
{
    switch (o) {
    case AnnotationOrigin::Analysis: return "analysis";
    case AnnotationOrigin::User:     return "user";
    case AnnotationOrigin::Ai:       return "ai";
    default:                         return "?";
    }
}

void AnnotationStore::set_name(EntityId id, NameAnnotation name)
{
    // A user-authored name is never silently replaced by analysis output.
    auto existing = names_.find(id);
    if (existing != names_.end()
        && existing->second.origin == AnnotationOrigin::User
        && name.origin != AnnotationOrigin::User) {
        return;
    }
    names_[id] = std::move(name);
}

const NameAnnotation* AnnotationStore::name_of(EntityId id) const
{
    auto it = names_.find(id);
    return it == names_.end() ? nullptr : &it->second;
}

std::optional<std::string> AnnotationStore::display_name(EntityId id) const
{
    const NameAnnotation* name = name_of(id);
    if (name == nullptr) {
        return std::nullopt;
    }
    // Rejected model suggestions are retained for audit but never displayed.
    if (name->origin == AnnotationOrigin::Ai && name->review == ReviewState::Rejected) {
        return std::nullopt;
    }
    return name->name;
}

void AnnotationStore::add_comment(EntityId id, CommentAnnotation comment)
{
    comments_[id].push_back(std::move(comment));
}

const std::vector<CommentAnnotation>* AnnotationStore::comments_of(EntityId id) const
{
    auto it = comments_.find(id);
    return it == comments_.end() ? nullptr : &it->second;
}

void AnnotationStore::set_type(EntityId id, TypeAnnotation type)
{
    auto existing = types_.find(id);
    if (existing != types_.end()
        && existing->second.origin == AnnotationOrigin::User
        && type.origin != AnnotationOrigin::User) {
        return;
    }
    types_[id] = std::move(type);
}

const TypeAnnotation* AnnotationStore::type_of(EntityId id) const
{
    auto it = types_.find(id);
    return it == types_.end() ? nullptr : &it->second;
}

void AnnotationStore::add_tag(EntityId id, TagAnnotation tag)
{
    tags_[id].push_back(std::move(tag));
}

const std::vector<TagAnnotation>* AnnotationStore::tags_of(EntityId id) const
{
    auto it = tags_.find(id);
    return it == tags_.end() ? nullptr : &it->second;
}

std::vector<EntityId> AnnotationStore::entities_with_tag(const std::string& tag) const
{
    std::vector<EntityId> result;
    for (const auto& [id, list] : tags_) {
        for (const auto& t : list) {
            if (t.tag == tag) {
                result.push_back(id);
                break;
            }
        }
    }
    return result;
}

void AnnotationStore::clear_analysis_annotations()
{
    // Regenerable output is dropped; human and model contributions survive.
    for (auto it = names_.begin(); it != names_.end();) {
        it = (it->second.origin == AnnotationOrigin::Analysis) ? names_.erase(it) : std::next(it);
    }
    for (auto it = types_.begin(); it != types_.end();) {
        it = (it->second.origin == AnnotationOrigin::Analysis) ? types_.erase(it) : std::next(it);
    }
    for (auto& [id, list] : comments_) {
        std::erase_if(list, [](const CommentAnnotation& c) {
            return c.origin == AnnotationOrigin::Analysis;
        });
    }
    for (auto& [id, list] : tags_) {
        std::erase_if(list, [](const TagAnnotation& t) {
            return t.origin == AnnotationOrigin::Analysis;
        });
    }
}

void AnnotationStore::set_review_state(EntityId id, ReviewState state)
{
    auto it = names_.find(id);
    if (it != names_.end()) {
        it->second.review = state;
    }
}

} // namespace sp::db
