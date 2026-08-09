/*
 * benchmark.c - Ground-truth corpus for measuring AI lifting accuracy.
 *
 * Every function here is deliberately a different SHAPE, so the lifted output
 * can be compared against known-correct source. This is the only way to measure
 * lifting accuracy: with notepad.exe you can tell that the model produced
 * something, but not whether it produced the right thing.
 *
 * Keep each function small and single-purpose. The point is not realism, it is
 * having an unambiguous correct answer for each case.
 *
 * Build with build.bat (release /O2 and debug /Od, both worth testing - the
 * optimiser changes control flow dramatically).
 *
 * Every function is exported so the engine finds it as a Certain candidate and
 * boundary accuracy is never the variable under test.
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

#define API __declspec(dllexport)

/* --- 1. Baseline: straight-line arithmetic, no control flow ------------- */
API int bm_add_scaled(int a, int b)
{
    return (a * 3) + (b * 7) - 11;
}

/* --- 2. Single counted loop with an accumulator ------------------------- */
API int bm_sum_to_n(int n)
{
    int total = 0;
    for (int i = 1; i <= n; ++i) {
        total += i;
    }
    return total;
}

/* --- 3. Nested loops: tests loop-nesting depth recovery ---------------- */
API int bm_matrix_trace(const int* matrix, int side)
{
    int total = 0;
    for (int row = 0; row < side; ++row) {
        for (int col = 0; col < side; ++col) {
            if (row == col) {
                total += matrix[(row * side) + col];
            }
        }
    }
    return total;
}

/* --- 4. Dense switch: compiles to a jump table ------------------------- */
/* This is the case that produces has_unresolved_exit until jump-table
   resolution lands. Good regression target for that work. */
API const char* bm_classify(int code)
{
    switch (code) {
    case 0:  return "none";
    case 1:  return "read";
    case 2:  return "write";
    case 3:  return "append";
    case 4:  return "truncate";
    case 5:  return "execute";
    case 6:  return "delete";
    case 7:  return "rename";
    default: return "unknown";
    }
}

/* --- 5. Early-return cascade: many blocks, one shared exit ------------- */
API int bm_validate(int value, int lower, int upper)
{
    if (value < lower)  return -1;
    if (value > upper)  return -2;
    if (value == 0)     return -3;
    if ((value % 2) != 0) return 1;
    return 0;
}

/* --- 6. String walk: gives the model a string constant to work with ---- */
API int bm_count_char(const char* text, char needle)
{
    int count = 0;
    while (*text != '\0') {
        if (*text == needle) {
            ++count;
        }
        ++text;
    }
    return count;
}

/* --- 7. Recursion: tests call-graph cycle detection ------------------- */
API unsigned long long bm_factorial(unsigned n)
{
    if (n <= 1) {
        return 1;
    }
    return n * bm_factorial(n - 1);
}

/* --- 8. Mutual recursion: tests SCC detection in the call graph -------- */
API int bm_is_even(int n);
API int bm_is_odd(int n);

API int bm_is_even(int n)
{
    if (n == 0) return 1;
    return bm_is_odd(n - 1);
}

API int bm_is_odd(int n)
{
    if (n == 0) return 0;
    return bm_is_even(n - 1);
}

/* --- 9. Windows API usage: the strongest AI signal there is ------------ */
/* A model given the resolved names CreateFileW / ReadFile / CloseHandle
   should identify this immediately, even without good pseudocode. */
API int bm_read_first_bytes(const wchar_t* path, unsigned char* out, unsigned count)
{
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return -1;
    }

    DWORD got = 0;
    if (!ReadFile(file, out, count, &got, NULL)) {
        CloseHandle(file);
        return -2;
    }

    CloseHandle(file);
    return (int)got;
}

/* --- 10. Registry write: a recognisable behaviour pattern -------------- */
/* Writing to the Run key is textbook persistence. Any behaviour detector or
   AI narrative worth having must flag this one. */
API int bm_set_run_key(const wchar_t* name, const wchar_t* command)
{
    HKEY key;
    LONG status = RegCreateKeyExW(HKEY_CURRENT_USER,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, NULL, 0, KEY_SET_VALUE, NULL, &key, NULL);

    if (status != ERROR_SUCCESS) {
        return -1;
    }

    const DWORD bytes = (DWORD)((wcslen(command) + 1) * sizeof(wchar_t));
    status = RegSetValueExW(key, name, 0, REG_SZ,
                            (const BYTE*)command, bytes);
    RegCloseKey(key);
    return (status == ERROR_SUCCESS) ? 0 : -2;
}

/* --- 11. Struct and pointer work: tests type inference --------------- */
typedef struct {
    unsigned id;
    unsigned flags;
    char label[16];
} bm_record;

API int bm_find_record(const bm_record* records, unsigned n, unsigned id)
{
    for (unsigned i = 0; i < n; ++i) {
        if (records[i].id == id) {
            return (int)i;
        }
    }
    return -1;
}

/* --- 12. Deliberately unsafe: target for the findings layer ----------- */
/* Unbounded copy into a fixed stack buffer. This is a Tier-2 vulnerability
   INDICATOR - a risky pattern, not a proven exploitable bug. Useful for
   testing that the findings layer flags it and describes it honestly. */
API void bm_unsafe_copy(const char* input)
{
    char buffer[32];
    strcpy(buffer, input);          /* no bounds check - intentional */
    OutputDebugStringA(buffer);
}

/* --- 13. Weak crypto constant: another findings-layer target ---------- */
/* The MD5 initialisation constants. A findings layer should recognise these
   and note MD5 is unsuitable for security use. */
API void bm_md5_init(unsigned* state)
{
    state[0] = 0x67452301u;
    state[1] = 0xEFCDAB89u;
    state[2] = 0x98BADCFEu;
    state[3] = 0x10325476u;
}

/* Keeps the linker happy for an EXE build; harmless for a DLL. */
int main(void)
{
    printf("%d\n", bm_sum_to_n(10));
    return 0;
}
