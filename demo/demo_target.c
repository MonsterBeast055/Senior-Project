/*
 * demo_target.c - A deliberately analysable Windows program.
 *
 * Built to be pulled apart on stage. Nothing here is clever; everything is
 * chosen so that some part of the analysis pipeline has something to say about
 * it, and so that anyone reading the decompiled output can check it against
 * this file line by line.
 *
 * THE SHAPE THAT MATTERS
 *
 * The engine's reachability pass searches forward from any function that calls
 * an input-reading API, through the call graph, looking for risky operations.
 * So the program is written the way a real configuration loader is written: the
 * routine that reads the file is also the routine that acts on what it read.
 *
 *   load_and_apply_config      reads the file        <- INPUT SOURCE (ReadFile)
 *     -> parse_directive       splits name = value
 *        -> apply_directive    a switch over the name
 *           -> launch_helper       CreateProcessW    <- SINK, 4 hops away
 *           -> load_plugin         LoadLibraryW      <- SINK
 *           -> record_run          RegSetValueExA    <- SINK
 *           -> make_page_writable  VirtualProtect    <- SINK
 *           -> copy_setting        strcpy            <- SINK, the headline one
 *
 * All eight risky operations are reported as REACHABLE with a real call path,
 * which is the distinction the whole project is built around: a risky call that
 * untrusted input can arrive at is a different claim from a risky call sitting
 * on its own. The headline finding is
 *
 *   unbounded-copy   HIGH   5 hops
 *   load_and_apply_config > parse_directive > apply_directive > copy_setting
 *                                                             > strcpy
 *
 * WHY THIS BUILD USES /MD, AND WHY THAT MATTERS
 *
 * Risky-operation classification works from the import table. Microsoft's C
 * runtime is linked statically by default (/MT), which puts strcpy inside the
 * executable with no import entry and no name to classify - the defect below is
 * then completely invisible to the analysis. Building with /MD imports the CRT
 * from api-ms-win-crt-string-l1-1-0.dll, so strcpy appears in the import table
 * and is classified as an unbounded copy.
 *
 * Worth demonstrating both ways if there is time: rebuild with /MT and the
 * high-severity finding disappears. That is a real, explainable limit of
 * import-based classification rather than a defect in the tool.
 *
 * OTHER THINGS TO POINT AT
 *
 *   compute_checksum    a counted loop with a rotate - the construct a
 *                       decompiler most often reproduces as shifts and an or
 *                       rather than recognising as a rotation. The best single
 *                       function for a source-versus-decompiled comparison.
 *   load_plugin         resolves GetTickCount through GetProcAddress, so the
 *                       only evidence of its use is a string beside the call.
 *                       This is the pattern that defeats static import analysis.
 *   make_page_writable  makes a page writable AND executable at runtime, which
 *                       is the same violation the hardener detects at section
 *                       level in the file - and shows why a header flag alone
 *                       is not a complete answer.
 *
 * It is an ordinary, harmless program: it reads a text file, prints a checksum,
 * and can start Notepad.
 *
 * BUILD: see build_demo.bat, which also explains every linker flag.
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Forward declarations, so the call chain below reads top-down. */
static void parse_directive(char *line);
static int  apply_directive(int command, const char *value);

/* --- 1. The unsafe copy ------------------------------------------------- */

/*
 * Copies a setting into a fixed 64-byte buffer with no length check.
 *
 * DELIBERATE DEFECT (CWE-121, stack buffer overflow). A config value longer
 * than 63 characters writes past the end of `local`.
 *
 * This is the finding the demonstration is built around: reported HIGH, and
 * reported as reachable from untrusted input through five hops. Both halves
 * matter - the engine rates it High because an unbounded copy is serious AND
 * because a path to it exists. An identical strcpy that nothing could reach
 * would be downgraded rather than dropped.
 */
static void copy_setting(const char *value)
{
    char local[64];

    strcpy(local, value);   /* no bounds check: that is the bug */

    printf("  setting applied: %s\n", local);
}

/* --- 2. A counted loop -------------------------------------------------- */

/*
 * Sums the bytes of a buffer with a rotate, giving a loop with a carried
 * dependency. The most interesting function to compare against its decompiled
 * form.
 */
static unsigned int compute_checksum(const unsigned char *data, int length)
{
    unsigned int sum = 0;
    int index = 0;

    for (index = 0; index < length; ++index) {
        sum = (sum << 3) | (sum >> 29);   /* rotate left by 3 */
        sum += data[index];
    }

    return sum;
}

/* --- 3. Sinks ----------------------------------------------------------- */

/* Starts Notepad. Harmless, and enough for CreateProcessW to be recorded as a
 * process-execution capability with a reachable call path. */
static int launch_helper(const char *reason)
{
    STARTUPINFOW startup;
    PROCESS_INFORMATION process;
    wchar_t command[] = L"notepad.exe";
    DWORD exit_code = 0;

    printf("  launching helper (%s)\n", reason);

    ZeroMemory(&startup, sizeof(startup));
    startup.cb = sizeof(startup);
    ZeroMemory(&process, sizeof(process));

    if (!CreateProcessW(NULL, command, NULL, NULL, FALSE,
                        CREATE_NEW_CONSOLE, NULL, NULL, &startup, &process)) {
        printf("  could not start helper (%lu)\n", GetLastError());
        return 0;
    }

    WaitForSingleObject(process.hProcess, 2000);
    GetExitCodeProcess(process.hProcess, &exit_code);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return 1;
}

/* Resolves a function at runtime rather than through the import table. */
static int load_plugin(const char *name)
{
    HMODULE library;
    FARPROC entry;

    printf("  resolving for '%s'\n", name);

    library = LoadLibraryW(L"kernel32.dll");
    if (library == NULL) {
        return 0;
    }

    entry = GetProcAddress(library, "GetTickCount");
    if (entry == NULL) {
        FreeLibrary(library);
        return 0;
    }

    printf("  resolved GetTickCount at %p\n", (void *)entry);
    FreeLibrary(library);
    return 1;
}

/* Makes a page both writable and executable, at runtime. */
static int make_page_writable(void)
{
    static unsigned char scratch[256];
    DWORD previous = 0;

    if (!VirtualProtect(scratch, sizeof(scratch),
                        PAGE_EXECUTE_READWRITE, &previous)) {
        return 0;
    }

    scratch[0] = 0xC3;   /* ret */
    VirtualProtect(scratch, sizeof(scratch), previous, &previous);
    printf("  scratch page was made writable and executable\n");
    return 1;
}

/* Writes a value under HKCU - ordinary behaviour, and persistence evidence. */
static int record_run(const char *value)
{
    HKEY key;
    LONG status;

    status = RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\SeniorProjectDemo",
                             0, NULL, 0, KEY_WRITE, NULL, &key, NULL);
    if (status != ERROR_SUCCESS) {
        return 0;
    }

    RegSetValueExA(key, "LastSetting", 0, REG_SZ,
                   (const BYTE *)value, (DWORD)(strlen(value) + 1));
    RegCloseKey(key);
    printf("  run recorded in the registry\n");
    return 1;
}

/* Appends a line to a log file. */
static int write_log(const char *text)
{
    HANDLE file;
    DWORD written = 0;

    file = CreateFileA("demo_target.log", FILE_APPEND_DATA, FILE_SHARE_READ,
                       NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return 0;
    }

    WriteFile(file, text, (DWORD)strlen(text), &written, NULL);
    WriteFile(file, "\r\n", 2, &written, NULL);
    CloseHandle(file);
    return 1;
}

/* --- 4. Dispatch -------------------------------------------------------- */

/*
 * Dispatches to one of six handlers.
 *
 * Written as an if/else chain rather than a switch, and the reason is worth
 * demonstrating in its own right. A dense switch compiles to a jump table -
 * an indirect jump through memory - and the disassembler cannot statically
 * resolve where that jump goes. The case bodies then fall outside this
 * function's recovered control-flow graph, the calls inside them are never
 * attributed to this function, and every sink below becomes unreachable in the
 * call graph even though the program plainly reaches them.
 *
 * That is a genuine limitation of static analysis, not a defect in the tool,
 * and the engine reports it honestly: unresolved indirect jumps are counted and
 * the affected functions are marked as having an incomplete graph. An if/else
 * chain compiles to direct conditional branches, which the disassembler follows
 * exactly.
 */
static int apply_directive(int command, const char *value)
{
    if (command == 1) {
        copy_setting(value);
        return 1;
    }
    if (command == 2) {
        return launch_helper(value);
    }
    if (command == 3) {
        return load_plugin(value);
    }
    if (command == 4) {
        return make_page_writable();
    }
    if (command == 5) {
        return record_run(value);
    }
    if (command == 6) {
        return write_log(value);
    }

    printf("  unknown directive %d\n", command);
    return 0;
}

/*
 * Splits "command=value" and hands it on. One more hop, so the reported path
 * has depth rather than being a single call.
 */
static void parse_directive(char *line)
{
    char *separator = strchr(line, '=');
    const char *value = "";
    int command = 0;

    if (separator != NULL) {
        *separator = '\0';
        value = separator + 1;
    }

    command = atoi(line);
    printf("  directive %d, value '%s'\n", command, value);

    apply_directive(command, value);
}

/* --- 5. Input source, and the head of the chain -------------------------- */

/*
 * Reads the configuration file and acts on it.
 *
 * Deliberately uses the Win32 API rather than fgets: the engine classifies APIs
 * by their import-table entry, and a statically linked CRT fgets has no import
 * entry to classify. ReadFile does, and is recognised as untrusted input.
 *
 * This function is the start of every call path the engine reports.
 */
static int load_and_apply_config(const char *path)
{
    char line[256];
    HANDLE file;
    DWORD got = 0;
    unsigned int checksum = 0;
    int index = 0;

    file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        printf("  no configuration at '%s'\n", path);
        return 0;
    }

    /* The untrusted read. */
    if (!ReadFile(file, line, (DWORD)(sizeof(line) - 1), &got, NULL) || got == 0) {
        CloseHandle(file);
        return 0;
    }
    CloseHandle(file);

    line[got] = '\0';
    for (index = 0; index < (int)got; ++index) {
        if (line[index] == '\n' || line[index] == '\r') {
            line[index] = '\0';
            break;
        }
    }

    printf("  read %d bytes of configuration\n", (int)strlen(line));

    checksum = compute_checksum((const unsigned char *)line, (int)strlen(line));
    printf("  checksum 0x%08X\n", checksum);

    parse_directive(line);
    return 1;
}

/* --- 6. Entry point ----------------------------------------------------- */

int main(int argc, char **argv)
{
    const char *path = "demo_config.txt";

    printf("Senior Project demonstration target\n");
    printf("usage: demo_target.exe [config file]\n");
    printf("config file holds one line: <1-6>=<value>\n");
    printf("  1=text  copy a setting   2=x  launch helper   3=x  load plugin\n");
    printf("  4=x     make page RWX    5=x  write registry  6=x  write log\n\n");

    if (argc > 1) {
        path = argv[1];
    }

    if (!load_and_apply_config(path)) {
        printf("  nothing to do\n");
    }

    printf("\ndone\n");
    return 0;
}
