#pragma once
//
// Error.h - Explicit error propagation.
//
// A library cannot print to stdout and call exit(). Every fallible operation
// returns Result<T>. Hand-rolled because std::expected is C++23 and we target
// C++20.
//
#include <string>
#include <utility>
#include <variant>
#include <cassert>

namespace sp::core {

enum class ErrorCode {
    Ok = 0,
    FileNotFound,
    NotAPeFile,
    UnsupportedArchitecture,
    SectionNotFound,
    DisassemblerInitFailed,
    DecodeFailed,
    InvalidAddress,
    InvalidArgument,
    Internal,
};

const char* to_string(ErrorCode c);

struct Error {
    ErrorCode code = ErrorCode::Internal;
    std::string message;

    Error() = default;
    Error(ErrorCode c, std::string msg) : code(c), message(std::move(msg)) {}
};

template <typename T>
class Result {
public:
    Result(T value) : storage_(std::move(value)) {}
    Result(Error error) : storage_(std::move(error)) {}

    bool ok() const { return std::holds_alternative<T>(storage_); }
    explicit operator bool() const { return ok(); }

    T& value() { assert(ok()); return std::get<T>(storage_); }
    const T& value() const { assert(ok()); return std::get<T>(storage_); }

    const Error& error() const { assert(!ok()); return std::get<Error>(storage_); }

private:
    std::variant<T, Error> storage_;
};

// Result for operations that either succeed or fail with no payload.
class Status {
public:
    Status() = default;
    Status(Error e) : error_(std::move(e)), failed_(true) {}

    // Named success() rather than ok() so it does not collide with the
    // ok() observer below.
    static Status success() { return Status(); }

    bool ok() const { return !failed_; }
    explicit operator bool() const { return ok(); }
    const Error& error() const { assert(failed_); return error_; }

private:
    Error error_;
    bool failed_ = false;
};

} // namespace sp::core
