#pragma once
//
// test_harness.h - Minimal assertion harness.
//
// Dependency-free on purpose: the suite must run with nothing installed.
//
#include <cstdio>
#include <string>
#include <vector>

namespace sp::test {

struct Failure {
    std::string test;
    std::string expression;
    std::string file;
    int line = 0;
};

inline std::vector<Failure>& failures()
{
    static std::vector<Failure> list;
    return list;
}

inline const char*& current_test()
{
    static const char* name = "";
    return name;
}

inline void record(const char* expression, const char* file, int line)
{
    failures().push_back({ current_test(), expression, file, line });
    std::printf("  FAIL %s:%d  %s\n", file, line, expression);
}

} // namespace sp::test

#define SP_TEST(name)                                                          \
    do {                                                                       \
        sp::test::current_test() = (name);                                      \
        std::printf("[test] %s\n", (name));                                     \
    } while (0)

#define SP_CHECK(expr)                                                         \
    do {                                                                       \
        if (!(expr)) {                                                         \
            sp::test::record(#expr, __FILE__, __LINE__);                        \
        }                                                                      \
    } while (0)

#define SP_CHECK_EQ(a, b)                                                      \
    do {                                                                       \
        if (!((a) == (b))) {                                                    \
            sp::test::record(#a " == " #b, __FILE__, __LINE__);                 \
        }                                                                      \
    } while (0)
