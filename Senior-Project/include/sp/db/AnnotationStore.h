#pragma once
//
// AnnotationStore.h - Inference and human intent, layered over facts.
//
// Holds everything that is not ground truth: names, types, comments,
// classifications. Each annotation records its origin (analysis pass, user, or
// model) so the UI can show provenance and so a re-analysis can discard its own
// previous output while preserving user edits.
//
// This is also the write target for the AI feedback loop. When the model
// concludes that a function is a key schedule, it lands here as an
// AiInferred annotation, becomes visible to subsequent analysis passes, and can
// be accepted or rejected without corrupting the underlying disassembly.
//
#include "sp/core/Types.h"
#include "sp/core/Provenance.h"
#include "EntityId.h"

#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace sp::db {

enum class AnnotationOrigin : std::uint8_t {
    Analysis = 0,  // produced by a deterministic pass; safe to regenerate
    User,          // human authored; never discarded automatically
    Ai,            // model authored; provisional until accepted
};

const char* to_string(AnnotationOrigin o);

enum class ReviewState : std::uint8_t {
    NotReviewed = 0,
    Accepted,
    Rejected,
};

struct NameAnnotation {
    std::string name;
    AnnotationOrigin origin = AnnotationOrigin::Analysis;
    ReviewState review = ReviewState::NotReviewed;
    core::Confidence confidence = core::Confidence::None;

    // Free-form justification. For AI-authored names this is the model's
    // reasoning, which is what makes the suggestion auditable.
    std::string rationale;
};

struct CommentAnnotation {
    std::string text;
    AnnotationOrigin origin = AnnotationOrigin::Analysis;
};

// A guessed or asserted type for a function, parameter or data object. Kept
// deliberately loose at this stage; a full type system is future work.
struct TypeAnnotation {
    std::string type_expr;   // e.g. "int (*)(char*, unsigned)"
    AnnotationOrigin origin = AnnotationOrigin::Analysis;
    core::Confidence confidence = core::Confidence::None;
};

// Semantic labels that make the binary queryable: "crypto", "network",
// "registry-access", "anti-debug". Populated by both heuristics and the model,
// and the basis for natural-language search over the binary.
struct TagAnnotation {
    std::string tag;
    AnnotationOrigin origin = AnnotationOrigin::Analysis;
    core::Confidence confidence = core::Confidence::None;
};

class AnnotationStore {
public:
    // --- Names ------------------------------------------------------------
    void set_name(EntityId id, NameAnnotation name);
    const NameAnnotation* name_of(EntityId id) const;

    // Highest-priority display name: User > accepted Ai > Analysis.
    std::optional<std::string> display_name(EntityId id) const;

    // --- Comments ---------------------------------------------------------
    void add_comment(EntityId id, CommentAnnotation comment);
    const std::vector<CommentAnnotation>* comments_of(EntityId id) const;

    // --- Types ------------------------------------------------------------
    void set_type(EntityId id, TypeAnnotation type);
    const TypeAnnotation* type_of(EntityId id) const;

    // --- Tags -------------------------------------------------------------
    void add_tag(EntityId id, TagAnnotation tag);
    const std::vector<TagAnnotation>* tags_of(EntityId id) const;
    std::vector<EntityId> entities_with_tag(const std::string& tag) const;

    // --- Lifecycle --------------------------------------------------------
    // Drop everything produced by deterministic passes, keeping user and AI
    // annotations. Called before a re-analysis.
    void clear_analysis_annotations();

    // Review workflow for model output.
    void set_review_state(EntityId id, ReviewState state);

private:
    std::unordered_map<EntityId, NameAnnotation> names_;
    std::unordered_map<EntityId, std::vector<CommentAnnotation>> comments_;
    std::unordered_map<EntityId, TypeAnnotation> types_;
    std::unordered_map<EntityId, std::vector<TagAnnotation>> tags_;
};

} // namespace sp::db
