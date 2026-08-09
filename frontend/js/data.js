/*
 * data.js - Sample analysis output, and the adapter that loads real output.
 *
 * The sample is NOT invented. The function at 0x140002418 is the real CFG the
 * engine produced for C:\Windows\System32\notepad.exe: 20 blocks, 34 edges,
 * every instruction as Capstone decoded it. It is the MSVC CRT's CPU feature
 * detection routine (__isa_available_init) - the "GenuineIntel" vendor check is
 * visible in the xor constants.
 *
 * Using real output matters: a mock built from imagination would have let the
 * UI make assumptions the engine does not actually satisfy.
 *
 * Everything is embedded rather than fetched so index.html works by
 * double-clicking it. Browsers block fetch() on file:// URLs, so a fetch-based
 * sample would need a web server just to look at the layout.
 */

const SP = (function () {

    // --- Sample: image -------------------------------------------------
    const image = {
        schema_version: "1.0",
        format: "pe",
        arch: "x86_64",
        image_base: "0x140000000",
        entry_point: "0x1400019c0",
        image_size: 360448,
        sections: [
            { name: ".text",  va: "0x140001000", virtual_size: 157666, raw_size: 159744, executable: true,  readable: true,  writable: false, entropy: 6.2820 },
            { name: "fothk",  va: "0x140028000", virtual_size: 4096,   raw_size: 4096,   executable: true,  readable: true,  writable: false, entropy: 0.0159 },
            { name: ".rdata", va: "0x140029000", virtual_size: 42696,  raw_size: 45056,  executable: false, readable: true,  writable: false, entropy: 5.8041 },
            { name: ".data",  va: "0x140034000", virtual_size: 10048,  raw_size: 4096,   executable: false, readable: true,  writable: true,  entropy: 1.6243 },
            { name: ".pdata", va: "0x140037000", virtual_size: 4632,   raw_size: 8192,   executable: false, readable: true,  writable: false, entropy: 5.1376 },
            { name: ".rsrc",  va: "0x14003a000", virtual_size: 123344, raw_size: 126976, executable: false, readable: true,  writable: false, entropy: 7.0998 },
            { name: ".reloc", va: "0x140059000", virtual_size: 860,    raw_size: 4096,   executable: false, readable: true,  writable: false, entropy: 4.9582 }
        ],
        imports: [
            { library: "api-ms-win-core-file-l1-1-0.dll",     name: "CreateFileW",      iat_slot: "0x140029de8" },
            { library: "api-ms-win-core-file-l1-1-0.dll",     name: "ReadFile",         iat_slot: "0x140029df0" },
            { library: "api-ms-win-core-file-l1-1-0.dll",     name: "WriteFile",        iat_slot: "0x140029e10" },
            { library: "api-ms-win-core-registry-l1-1-0.dll", name: "RegCreateKeyExW",  iat_slot: "0x14002a068" },
            { library: "api-ms-win-core-registry-l1-1-0.dll", name: "RegSetValueExW",   iat_slot: "0x14002a070" },
            { library: "api-ms-win-core-registry-l1-1-0.dll", name: "RegCloseKey",      iat_slot: "0x14002a058" },
            { library: "USER32.dll",                          name: "MessageBoxW",      iat_slot: "0x140029a78" },
            { library: "USER32.dll",                          name: "SendMessageW",     iat_slot: "0x140029c90" },
            { library: "api-ms-win-core-debug-l1-1-0.dll",    name: "IsDebuggerPresent",iat_slot: "0x140029d40" },
            { library: "api-ms-win-crt-string-l1-1-0.dll",    name: "memset",           iat_slot: "0x14002a3c8" }
        ],
        coverage: {
            executable_bytes: 161762,
            code_fraction: 0.9440,
            instruction_count: 38202,
            function_count: 452
        }
    };

    // --- Sample: function index ------------------------------------------
    const functions = [
        { va: "0x140002418", name: "sub_140002418", block_count: 20, instruction_count: 106,
          information_score: 21, cyclomatic_complexity: 16, api_call_count: 0, string_count: 0,
          is_thunk: false, confidence: "certain", content_hash: 12297829382473034410 },
        { va: "0x1400023a0", name: "sub_1400023a0", block_count: 9, instruction_count: 61,
          information_score: 74, cyclomatic_complexity: 7, api_call_count: 5, string_count: 2,
          is_thunk: false, confidence: "certain", content_hash: 9832718239817231 },
        { va: "0x1400019c0", name: "sub_1400019c0", block_count: 1, instruction_count: 4,
          information_score: 0, cyclomatic_complexity: 1, api_call_count: 0, string_count: 0,
          is_thunk: false, confidence: "certain", content_hash: 771231237812 },
        { va: "0x14000da7c", name: "sub_14000da7c", block_count: 161, instruction_count: 778,
          information_score: 55, cyclomatic_complexity: 92, api_call_count: 4, string_count: 3,
          is_thunk: false, confidence: "certain", content_hash: 5512312378123 },
        { va: "0x140013154", name: "sub_140013154", block_count: 1620, instruction_count: 11304,
          information_score: 61, cyclomatic_complexity: 640, api_call_count: 7, string_count: 1,
          is_thunk: false, confidence: "certain", content_hash: 88123123781 },
        { va: "0x140001094", name: "sub_140001094", block_count: 10, instruction_count: 67,
          information_score: 33, cyclomatic_complexity: 8, api_call_count: 2, string_count: 1,
          is_thunk: false, confidence: "certain", content_hash: 4412312378 },
        { va: "0x140001040", name: "CreateFileW_thunk", block_count: 1, instruction_count: 1,
          information_score: 0, cyclomatic_complexity: 1, api_call_count: 1, string_count: 0,
          is_thunk: true, is_imported_stub: true, confidence: "high", content_hash: 1 }
    ];

    // --- Sample: the real 0x140002418 CFG --------------------------------
    function ins(va, size, mnemonic, operands, flow, target, target_name) {
        return {
            va: va, size: size, mnemonic: mnemonic, operands: operands || "",
            flow: flow || "sequential",
            target: target || null, target_name: target_name || null,
            indirect: false, memory_ref: null, confidence: "certain"
        };
    }
    function blk(start, end, instructions, successors, unresolved) {
        return {
            start: start, end: end, instruction_count: instructions.length,
            has_unresolved_exit: !!unresolved,
            instructions: instructions, successors: successors, predecessors: []
        };
    }
    const T = function (t) { return { target: t, kind: "taken", confidence: "high" }; };
    const F = function (t) { return { target: t, kind: "fall-through", confidence: "high" }; };
    const J = function (t) { return { target: t, kind: "jump", confidence: "high" }; };

    const detail_140002418 = {
        va: "0x140002418",
        name: "sub_140002418",
        extent_end: "0x1400025c4",
        convention: "win64",
        is_thunk: false, is_imported_stub: false, returns: true, is_library_code: false,
        instruction_count: 106, indirect_call_count: 0,
        content_hash: 12297829382473034410,
        cyclomatic_complexity: 16,
        information_score: 21,
        confidence: "certain",
        reachable_from_input: false,
        input_sources: [],
        api_calls: [],
        referenced_strings: [],
        provenance: [
            { kind: "pe-unwind-info", confidence: "certain", source: null }
        ],
        frame: { local_size: 16, saved_regs_size: 0, uses_frame_pointer: false },
        block_order: ["0x140002418","0x140002471","0x140002490","0x140002497","0x14000249e",
                      "0x1400024a8","0x1400024b8","0x1400024cc","0x1400024d3","0x1400024e0",
                      "0x1400024fc","0x140002506","0x140002521","0x140002539","0x14000253f",
                      "0x14000255b","0x14000257a","0x14000259a","0x1400025a5","0x1400025b2"],
        blocks: [
            blk("0x140002418","0x140002471",[
                ins("0x140002418",5,"mov","qword ptr [rsp + 0x10], rbx"),
                ins("0x14000241d",5,"mov","qword ptr [rsp + 0x18], rsi"),
                ins("0x140002422",1,"push","rdi"),
                ins("0x140002423",4,"sub","rsp, 0x10"),
                ins("0x140002427",2,"xor","eax, eax"),
                ins("0x140002429",2,"xor","ecx, ecx"),
                ins("0x14000242b",2,"cpuid"),
                ins("0x14000242d",3,"mov","r8d, ecx"),
                ins("0x140002430",3,"xor","r11d, r11d"),
                ins("0x140002433",3,"mov","r10d, edx"),
                ins("0x140002436",7,"xor","r8d, 0x6c65746e"),
                ins("0x14000243d",7,"xor","r10d, 0x49656e69"),
                ins("0x140002444",3,"mov","r9d, ebx"),
                ins("0x140002447",2,"mov","esi, eax"),
                ins("0x140002449",2,"xor","ecx, ecx"),
                ins("0x14000244b",4,"lea","eax, [r11 + 1]"),
                ins("0x14000244f",3,"or","r10d, r8d"),
                ins("0x140002452",2,"cpuid"),
                ins("0x140002454",7,"xor","r9d, 0x756e6547"),
                ins("0x14000245b",3,"mov","dword ptr [rsp], eax"),
                ins("0x14000245e",3,"or","r10d, r9d"),
                ins("0x140002461",4,"mov","dword ptr [rsp + 4], ebx"),
                ins("0x140002465",2,"mov","edi, ecx"),
                ins("0x140002467",4,"mov","dword ptr [rsp + 8], ecx"),
                ins("0x14000246b",4,"mov","dword ptr [rsp + 0xc], edx"),
                ins("0x14000246f",2,"jne","0x1400024cc","conditional-jump","0x1400024cc")
            ],[T("0x1400024cc"), F("0x140002471")]),

            blk("0x140002471","0x140002490",[
                ins("0x140002471",8,"or","qword ptr [rip + 0x31fdf], 0xffffffffffffffff"),
                ins("0x140002479",5,"and","eax, 0xfff3ff0"),
                ins("0x14000247e",11,"mov","qword ptr [rip + 0x31fc7], 0x8000"),
                ins("0x140002489",5,"cmp","eax, 0x106c0"),
                ins("0x14000248e",2,"je","0x1400024b8","conditional-jump","0x1400024b8")
            ],[T("0x1400024b8"), F("0x140002490")]),

            blk("0x140002490","0x140002497",[
                ins("0x140002490",5,"cmp","eax, 0x20660"),
                ins("0x140002495",2,"je","0x1400024b8","conditional-jump","0x1400024b8")
            ],[T("0x1400024b8"), F("0x140002497")]),

            blk("0x140002497","0x14000249e",[
                ins("0x140002497",5,"cmp","eax, 0x20670"),
                ins("0x14000249c",2,"je","0x1400024b8","conditional-jump","0x1400024b8")
            ],[T("0x1400024b8"), F("0x14000249e")]),

            blk("0x14000249e","0x1400024a8",[
                ins("0x14000249e",5,"add","eax, 0xfffcf9b0"),
                ins("0x1400024a3",3,"cmp","eax, 0x20"),
                ins("0x1400024a6",2,"ja","0x1400024cc","conditional-jump","0x1400024cc")
            ],[T("0x1400024cc"), F("0x1400024a8")]),

            blk("0x1400024a8","0x1400024b8",[
                ins("0x1400024a8",10,"movabs","rcx, 0x100010001"),
                ins("0x1400024b2",4,"bt","rcx, rax"),
                ins("0x1400024b6",2,"jae","0x1400024cc","conditional-jump","0x1400024cc")
            ],[T("0x1400024cc"), F("0x1400024b8")]),

            blk("0x1400024b8","0x1400024cc",[
                ins("0x1400024b8",7,"mov","r8d, dword ptr [rip + 0x32de5]"),
                ins("0x1400024bf",4,"or","r8d, 1"),
                ins("0x1400024c3",7,"mov","dword ptr [rip + 0x32dda], r8d"),
                ins("0x1400024ca",2,"jmp","0x1400024d3","unconditional-jump","0x1400024d3")
            ],[J("0x1400024d3")]),

            blk("0x1400024cc","0x1400024d3",[
                ins("0x1400024cc",7,"mov","r8d, dword ptr [rip + 0x32dd1]")
            ],[F("0x1400024d3")]),

            blk("0x1400024d3","0x1400024e0",[
                ins("0x1400024d3",5,"mov","eax, 7"),
                ins("0x1400024d8",4,"lea","r9d, [rax - 5]"),
                ins("0x1400024dc",2,"cmp","esi, eax"),
                ins("0x1400024de",2,"jl","0x140002506","conditional-jump","0x140002506")
            ],[T("0x140002506"), F("0x1400024e0")]),

            blk("0x1400024e0","0x1400024fc",[
                ins("0x1400024e0",2,"xor","ecx, ecx"),
                ins("0x1400024e2",2,"cpuid"),
                ins("0x1400024e4",3,"mov","dword ptr [rsp], eax"),
                ins("0x1400024e7",3,"mov","r11d, ebx"),
                ins("0x1400024ea",4,"mov","dword ptr [rsp + 4], ebx"),
                ins("0x1400024ee",4,"mov","dword ptr [rsp + 8], ecx"),
                ins("0x1400024f2",4,"mov","dword ptr [rsp + 0xc], edx"),
                ins("0x1400024f6",4,"bt","ebx, 9"),
                ins("0x1400024fa",2,"jae","0x140002506","conditional-jump","0x140002506")
            ],[T("0x140002506"), F("0x1400024fc")]),

            blk("0x1400024fc","0x140002506",[
                ins("0x1400024fc",3,"or","r8d, r9d"),
                ins("0x1400024ff",7,"mov","dword ptr [rip + 0x32d9e], r8d")
            ],[F("0x140002506")]),

            blk("0x140002506","0x140002521",[
                ins("0x140002506",10,"mov","dword ptr [rip + 0x31f38], 1"),
                ins("0x140002510",7,"mov","dword ptr [rip + 0x31f35], r9d"),
                ins("0x140002517",4,"bt","edi, 0x14"),
                ins("0x14000251b",6,"jae","0x1400025b2","conditional-jump","0x1400025b2")
            ],[T("0x1400025b2"), F("0x140002521")]),

            blk("0x140002521","0x140002539",[
                ins("0x140002521",7,"mov","dword ptr [rip + 0x31f20], r9d"),
                ins("0x140002528",5,"mov","ebx, 6"),
                ins("0x14000252d",6,"mov","dword ptr [rip + 0x31f19], ebx"),
                ins("0x140002533",4,"bt","edi, 0x1b"),
                ins("0x140002537",2,"jae","0x1400025b2","conditional-jump","0x1400025b2")
            ],[T("0x1400025b2"), F("0x140002539")]),

            blk("0x140002539","0x14000253f",[
                ins("0x140002539",4,"bt","edi, 0x1c"),
                ins("0x14000253d",2,"jae","0x1400025b2","conditional-jump","0x1400025b2")
            ],[T("0x1400025b2"), F("0x14000253f")]),

            blk("0x14000253f","0x14000255b",[
                ins("0x14000253f",2,"xor","ecx, ecx"),
                ins("0x140002541",3,"xgetbv"),
                ins("0x140002544",4,"shl","rdx, 0x20"),
                ins("0x140002548",3,"or","rdx, rax"),
                ins("0x14000254b",5,"mov","qword ptr [rsp + 0x20], rdx"),
                ins("0x140002550",5,"mov","rax, qword ptr [rsp + 0x20]"),
                ins("0x140002555",2,"and","al, bl"),
                ins("0x140002557",2,"cmp","al, bl"),
                ins("0x140002559",2,"jne","0x1400025b2","conditional-jump","0x1400025b2")
            ],[T("0x1400025b2"), F("0x14000255b")]),

            blk("0x14000255b","0x14000257a",[
                ins("0x14000255b",6,"mov","eax, dword ptr [rip + 0x31eeb]"),
                ins("0x140002561",3,"or","eax, 8"),
                ins("0x140002564",10,"mov","dword ptr [rip + 0x31eda], 3"),
                ins("0x14000256e",6,"mov","dword ptr [rip + 0x31ed8], eax"),
                ins("0x140002574",4,"test","r11b, 0x20"),
                ins("0x140002578",2,"je","0x1400025b2","conditional-jump","0x1400025b2")
            ],[T("0x1400025b2"), F("0x14000257a")]),

            blk("0x14000257a","0x14000259a",[
                ins("0x14000257a",3,"or","eax, 0x20"),
                ins("0x14000257d",10,"mov","dword ptr [rip + 0x31ec1], 5"),
                ins("0x140002587",6,"mov","dword ptr [rip + 0x31ebf], eax"),
                ins("0x14000258d",5,"mov","eax, 0xd0030000"),
                ins("0x140002592",3,"and","r11d, eax"),
                ins("0x140002595",3,"cmp","r11d, eax"),
                ins("0x140002598",2,"jne","0x1400025b2","conditional-jump","0x1400025b2")
            ],[T("0x1400025b2"), F("0x14000259a")]),

            blk("0x14000259a","0x1400025a5",[
                ins("0x14000259a",5,"mov","rax, qword ptr [rsp + 0x20]"),
                ins("0x14000259f",2,"and","al, 0xe0"),
                ins("0x1400025a1",2,"cmp","al, 0xe0"),
                ins("0x1400025a3",2,"jne","0x1400025b2","conditional-jump","0x1400025b2")
            ],[T("0x1400025b2"), F("0x1400025a5")]),

            blk("0x1400025a5","0x1400025b2",[
                ins("0x1400025a5",7,"or","dword ptr [rip + 0x31ea0], 0x40"),
                ins("0x1400025ac",6,"mov","dword ptr [rip + 0x31e96], ebx")
            ],[F("0x1400025b2")]),

            blk("0x1400025b2","0x1400025c4",[
                ins("0x1400025b2",5,"mov","rbx, qword ptr [rsp + 0x28]"),
                ins("0x1400025b7",2,"xor","eax, eax"),
                ins("0x1400025b9",5,"mov","rsi, qword ptr [rsp + 0x30]"),
                ins("0x1400025be",4,"add","rsp, 0x10"),
                ins("0x1400025c2",1,"pop","rdi"),
                ins("0x1400025c3",1,"ret","","return")
            ],[])
        ],
        callees: [],
        callers: [{ va: "0x1400019c0", name: "sub_1400019c0" }],
        unreachable_blocks: []
    };

    // --- Sample: a function with APIs and strings ------------------------
    const detail_1400023a0 = {
        va: "0x1400023a0", name: "sub_1400023a0", extent_end: "0x140002418",
        convention: "win64", is_thunk: false, returns: true, is_library_code: false,
        instruction_count: 61, indirect_call_count: 3,
        content_hash: 9832718239817231, cyclomatic_complexity: 7, information_score: 74,
        confidence: "certain",
        reachable_from_input: true,
        input_sources: ["registry"],
        api_calls: [
            "api-ms-win-core-registry-l1-1-0.dll!RegCreateKeyExW",
            "api-ms-win-core-registry-l1-1-0.dll!RegQueryValueExW",
            "api-ms-win-core-registry-l1-1-0.dll!RegSetValueExW",
            "api-ms-win-core-registry-l1-1-0.dll!RegCloseKey",
            "api-ms-win-crt-string-l1-1-0.dll!wcscpy"
        ],
        referenced_strings: [
            "SOFTWARE\\Microsoft\\Notepad",
            "iWindowPosDX"
        ],
        provenance: [{ kind: "pe-unwind-info", confidence: "certain", source: null }],
        frame: { local_size: 88, saved_regs_size: 8, uses_frame_pointer: false },
        block_order: ["0x1400023a0","0x1400023c8","0x1400023e0","0x140002400"],
        blocks: [
            blk("0x1400023a0","0x1400023c8",[
                ins("0x1400023a0",4,"sub","rsp, 0x58"),
                ins("0x1400023a4",7,"lea","rdx, [rip + 0x27c55]"),
                ins("0x1400023ab",3,"xor","r8d, r8d"),
                ins("0x1400023ae",7,"lea","rcx, [rip + 0x27c8b]"),
                ins("0x1400023b5",6,"call","qword ptr [rip + 0x27cad]","call",null,
                    "api-ms-win-core-registry-l1-1-0.dll!RegCreateKeyExW"),
                ins("0x1400023bb",3,"test","eax, eax"),
                ins("0x1400023be",6,"jne","0x140002400","conditional-jump","0x140002400")
            ],[T("0x140002400"), F("0x1400023c8")]),
            blk("0x1400023c8","0x1400023e0",[
                ins("0x1400023c8",5,"mov","rcx, qword ptr [rsp + 0x40]"),
                ins("0x1400023cd",7,"lea","rdx, [rip + 0x27c3a]"),
                ins("0x1400023d4",6,"call","qword ptr [rip + 0x27c96]","call",null,
                    "api-ms-win-core-registry-l1-1-0.dll!RegQueryValueExW"),
                ins("0x1400023da",3,"test","eax, eax"),
                ins("0x1400023dd",2,"jne","0x140002400","conditional-jump","0x140002400")
            ],[T("0x140002400"), F("0x1400023e0")]),
            blk("0x1400023e0","0x140002400",[
                ins("0x1400023e0",5,"lea","rcx, [rsp + 0x20]"),
                ins("0x1400023e5",5,"mov","rdx, qword ptr [rsp + 0x48]"),
                ins("0x1400023ea",6,"call","qword ptr [rip + 0x27c80]","call",null,
                    "api-ms-win-crt-string-l1-1-0.dll!wcscpy"),
                ins("0x1400023f0",5,"lea","rdx, [rsp + 0x20]"),
                ins("0x1400023f5",6,"call","qword ptr [rip + 0x27c75]","call",null,
                    "api-ms-win-core-registry-l1-1-0.dll!RegSetValueExW"),
                ins("0x1400023fb",5,"nop","dword ptr [rax]")
            ],[F("0x140002400")]),
            blk("0x140002400","0x140002418",[
                ins("0x140002400",5,"mov","rcx, qword ptr [rsp + 0x40]"),
                ins("0x140002405",6,"call","qword ptr [rip + 0x27c4d]","call",null,
                    "api-ms-win-core-registry-l1-1-0.dll!RegCloseKey"),
                ins("0x14000240b",2,"xor","eax, eax"),
                ins("0x14000240d",4,"add","rsp, 0x58"),
                ins("0x140002411",1,"ret","","return")
            ],[])
        ],
        callees: [],
        callers: [{ va: "0x140001094", name: "sub_140001094" }],
        unreachable_blocks: []
    };

    // --- Sample: findings -------------------------------------------------
    const findings = {
        schema_version: "1.0",
        methodology: {
            analysis: "call-graph reachability",
            value_level_dataflow: false,
            proves_exploitability: false,
            note: "Findings identify risky operations and whether a call path exists from a " +
                  "function reading untrusted input. This is a necessary condition for " +
                  "exploitability, not a sufficient one. Every finding requires manual review " +
                  "before being treated as a vulnerability."
        },
        input_sources: [
            { function: "0x1400023a0", function_name: "sub_1400023a0",
              api: "api-ms-win-core-registry-l1-1-0.dll!RegQueryValueExW", source: "registry" }
        ],
        findings: [
            {
                function: "0x1400023a0", function_name: "sub_1400023a0",
                api: "api-ms-win-crt-string-l1-1-0.dll!wcscpy",
                kind: "unbounded-copy", reachable_from_input: true,
                base_severity: "high", severity: "high", sources: ["registry"],
                call_path: [
                    { va: "0x1400023a0", name: "sub_1400023a0" }
                ],
                limitation: "A call path exists from a function that reads untrusted input to " +
                            "this operation. Value-level dataflow was not analysed, so it is not " +
                            "established that attacker-controlled data reaches the affected " +
                            "argument, nor that intervening length checks are absent. Manual " +
                            "review required to confirm exploitability."
            },
            {
                function: "0x1400023a0", function_name: "sub_1400023a0",
                api: "api-ms-win-core-registry-l1-1-0.dll!RegSetValueExW",
                kind: "registry-write", reachable_from_input: true,
                base_severity: "informational", severity: "informational", sources: ["registry"],
                call_path: [{ va: "0x1400023a0", name: "sub_1400023a0" }],
                limitation: "Registry writes are normal application behaviour on their own."
            },
            {
                function: "0x140001094", function_name: "sub_140001094",
                api: "api-ms-win-crt-string-l1-1-0.dll!memcpy",
                kind: "bounded-copy", reachable_from_input: false,
                base_severity: "low", severity: "informational", sources: [],
                call_path: [],
                limitation: "No call path from a known untrusted-input source was found. This " +
                            "may be because none exists, or because the path runs through an " +
                            "indirect call that static analysis cannot resolve."
            }
        ],
        summary: { risky_operations: 3, input_sources: 1, impactful: 1 }
    };

    // --- Sample: strings ---------------------------------------------------
    const strings = [
        { address: "0x14002a1f0", encoding: "utf16", text: "SOFTWARE\\Microsoft\\Notepad", refs: 3 },
        { address: "0x14002a240", encoding: "utf16", text: "iWindowPosDX", refs: 1 },
        { address: "0x14002a260", encoding: "utf16", text: "iWindowPosDY", refs: 1 },
        { address: "0x14002a2a0", encoding: "utf16", text: "lfFaceName", refs: 2 },
        { address: "0x14002a300", encoding: "utf16", text: "Untitled", refs: 4 },
        { address: "0x14002a340", encoding: "utf16", text: "*.txt", refs: 2 },
        { address: "0x14002a380", encoding: "ascii", text: "GenuineIntel", refs: 1 }
    ];

    // --- Sample: lifted C from the AI layer --------------------------------
    // Note the line_mapping: without it the decompiler pane and the graph cannot
    // be linked, which is the whole point of the side-by-side view.
    const lifted = {
        "0x1400023a0": {
            model: "sample",
            suggested_name: "load_notepad_settings",
            description: "Opens the Notepad settings key under HKCU, reads a value, copies it " +
                         "into a local buffer with wcscpy, writes it back, and closes the key.",
            confidence: "medium",
            review: "not-reviewed",
            c_code: [
                "int load_notepad_settings(void)",
                "{",
                "    HKEY  key;",
                "    WCHAR buffer[32];",
                "",
                "    if (RegCreateKeyExW(HKEY_CURRENT_USER,",
                "                        L\"SOFTWARE\\\\Microsoft\\\\Notepad\",",
                "                        0, NULL, 0, KEY_READ, NULL, &key, NULL) != 0)",
                "        return -1;",
                "",
                "    if (RegQueryValueExW(key, L\"iWindowPosDX\", ...) != 0)",
                "        goto done;",
                "",
                "    wcscpy(buffer, value);            /* no bounds check */",
                "    RegSetValueExW(key, ...);",
                "",
                "done:",
                "    RegCloseKey(key);",
                "    return 0;",
                "}"
            ],
            line_mapping: [
                { line: 5,  block: "0x1400023a0" },
                { line: 6,  block: "0x1400023a0" },
                { line: 7,  block: "0x1400023a0" },
                { line: 8,  block: "0x1400023a0" },
                { line: 10, block: "0x1400023c8" },
                { line: 11, block: "0x1400023c8" },
                { line: 13, block: "0x1400023e0" },
                { line: 14, block: "0x1400023e0" },
                { line: 16, block: "0x140002400" },
                { line: 17, block: "0x140002400" },
                { line: 18, block: "0x140002400" }
            ]
        },
        "0x140002418": {
            model: "sample",
            suggested_name: "detect_cpu_features",
            description: "Queries CPUID, checks for the GenuineIntel vendor string, tests " +
                         "specific feature bits and AVX state via XGETBV, then records the " +
                         "detected ISA level in globals. This is the MSVC CRT routine " +
                         "__isa_available_init.",
            confidence: "high",
            review: "not-reviewed",
            c_code: [
                "void detect_cpu_features(void)",
                "{",
                "    int regs[4];",
                "    __cpuid(regs, 0);",
                "",
                "    if (is_genuine_intel(regs)) {",
                "        /* model-specific errata checks */",
                "    }",
                "",
                "    if (max_leaf >= 7) {",
                "        __cpuidex(regs, 7, 0);",
                "        if (regs[1] & (1 << 9))",
                "            __isa_enabled |= ISA_AVAILABLE_SSE42;",
                "    }",
                "",
                "    if (osxsave_supported() && (_xgetbv(0) & 0x6) == 0x6)",
                "        __isa_available = __ISA_AVAILABLE_AVX;",
                "}"
            ],
            line_mapping: [
                { line: 3,  block: "0x140002418" },
                { line: 4,  block: "0x140002418" },
                { line: 6,  block: "0x140002471" },
                { line: 7,  block: "0x1400024b8" },
                { line: 10, block: "0x1400024d3" },
                { line: 11, block: "0x1400024e0" },
                { line: 12, block: "0x1400024e0" },
                { line: 13, block: "0x1400024fc" },
                { line: 16, block: "0x14000253f" },
                { line: 17, block: "0x14000255b" }
            ]
        }
    };

    const details = {
        "0x140002418": detail_140002418,
        "0x1400023a0": detail_1400023a0
    };

    // --- Adapter -----------------------------------------------------------
    // Two modes. "sample" serves the embedded data above so the UI runs with no
    // backend. "api" fetches from the backend, which runs the C++ engine and
    // stores what n8n sends back. The shapes are identical, so nothing in the
    // rest of the UI needs to know which is in use.
    let mode = "sample";
    let apiBase = "http://localhost:3000/api";
    let runId = "current";

    function configure(newMode, base) {
        mode = newMode;
        if (base) apiBase = base.replace(/\/+$/, "");
    }

    async function get(path, fallback) {
        if (mode === "sample") return fallback;
        const response = await fetch(apiBase + path, { headers: { Accept: "application/json" } });
        if (!response.ok) throw new Error(path + " -> HTTP " + response.status);
        return response.json();
    }

    return {
        configure: configure,
        currentMode: function () { return mode; },

        getImage:     function () { return get("/runs/" + runId + "/image", image); },
        getFunctions: function () { return get("/runs/" + runId + "/functions",
                                               { functions: functions, count: functions.length }); },
        getFindings:  function () { return get("/runs/" + runId + "/findings", findings); },
        getStrings:   function () { return get("/runs/" + runId + "/strings", { strings: strings }); },

        getFunction: function (va) {
            return get("/runs/" + runId + "/functions/" + va, details[va] || null);
        },

        // Lifted C is produced by n8n and stored by the API. Absent until the
        // AI pass has run, which is why every caller must handle null.
        getLifted: function (va) {
            return get("/runs/" + runId + "/functions/" + va + "/lifted", lifted[va] || null);
        }
    };
})();
