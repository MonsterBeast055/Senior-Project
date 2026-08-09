#!/usr/bin/env bash
# Stand-in for sp.exe. Emits the same stderr lines the real engine emits, with
# the same "[info] " prefix, so the backend's stage parser is tested against the
# real message shapes rather than against itself.
OUT=""
prev=""
for a in "$@"; do
  if [ "$prev" = "--out" ]; then OUT="$a"; fi
  prev="$a"
done
say() { echo "[info] $1" >&2; sleep 0.25; }
say "loaded /path/input.bin arch=x86_64 base=0x140000000 entry=0x140012345 sections=6 imports=112 exports=0 unwind_starts=452 tls_callbacks=0"
say "disassembled 38202 instructions (descent=37951 sweep=251 failures=3) coverage=0.944"
say "found 517 function candidates"
say "built 452 functions, 6424 blocks, 9240 edges (unresolved indirect jumps=46)"
say "extracted 182 strings (ascii=120 utf16=62)"
say "reachability: 9 sources, 31 risky operations, 4 impactful"
say "analysis complete in 1.84s: 452 functions, 38202 instructions, 5120 xrefs, 182 strings"
mkdir -p "$OUT/functions"
cat > "$OUT/image.json" <<'J'
{"schema_version":"1.0","arch":"x86_64","image_base":"0x140000000","entry_point":"0x140012345",
 "sections":[
   {"name":".text","va":"0x140001000","virtual_size":163840,"raw_size":163840,"readable":true,"writable":false,"executable":true,"entropy":6.42},
   {"name":".rdata","va":"0x140029000","virtual_size":40960,"raw_size":40960,"readable":true,"writable":false,"executable":false,"entropy":5.11}],
 "imports":[
   {"library":"KERNEL32.dll","name":"lstrcpyW","by_ordinal":false,"ordinal":0,"iat_slot":"0x140020100"},
   {"library":"ADVAPI32.dll","name":"RegSetValueExW","by_ordinal":false,"ordinal":0,"iat_slot":"0x140020108"}],
 "coverage":{"executable_bytes":163840,"code_fraction":0.944,"instruction_count":38202,"function_count":452},
 "strings":[
   {"address":"0x14001a000","encoding":"utf16","text":"Software\\Microsoft\\Windows\\CurrentVersion\\Run","length":45,"truncated":false,"refs":3,"library_only":false},
   {"address":"0x14001b200","encoding":"ascii","text":"(null)","length":6,"truncated":false,"refs":9,"library_only":true},
   {"address":"0x14001b300","encoding":"ascii","text":"ERROR: Unable to initialize heap","length":31,"truncated":false,"refs":2,"library_only":true}],
 "api_xrefs":[
   {"api":"ADVAPI32.dll!RegSetValueExW","count":2,
    "functions":[{"va":"0x1400023a0","name":"NPInit"},{"va":"0x140002418","name":"__isa_available_init"}]},
   {"api":"KERNEL32.dll!lstrcpyW","count":1,
    "functions":[{"va":"0x1400023a0","name":"NPInit"}]}],
 "string_xrefs":[
   {"address":"0x14001a000","count":1,
    "functions":[{"va":"0x1400023a0","name":"NPInit"}]}]}
J
cat > "$OUT/functions.json" <<'J'
{"schema_version":"1.0","functions":[
 {"va":"0x1400023a0","name":"NPInit","block_count":9,"edge_count":11,"instruction_count":61,"information_score":40,"api_call_count":2,"string_count":1,"cyclomatic_complexity":7,"caller_count":3,"callee_count":2,"is_library_code":false,"is_thunk":false,"is_imported_stub":false,"reachable_from_input":true,"content_hash":"0x22eece1ddc5e0f","processing_order":3},
 {"va":"0x140002500","name":"sub_140002500","block_count":2,"edge_count":1,"instruction_count":22,"information_score":7,"api_call_count":0,"string_count":0,"cyclomatic_complexity":2,"caller_count":1,"callee_count":0,"is_library_code":false,"is_thunk":false,"is_imported_stub":false,"reachable_from_input":false,"content_hash":"0x1111","processing_order":9},
 {"va":"0x140002418","name":"__isa_available_init","block_count":20,"edge_count":34,"instruction_count":106,"information_score":27,"api_call_count":1,"string_count":0,"cyclomatic_complexity":16,"caller_count":1,"callee_count":0,"is_library_code":false,"is_thunk":false,"is_imported_stub":false,"reachable_from_input":false,"content_hash":"0x8f1c2d3e4a5b6c7d","processing_order":7}]}
J
cat > "$OUT/findings.json" <<'J'
{"schema_version":"1.0","findings":[{"function":"0x1400023a0","function_name":"NPInit","api":"KERNEL32.dll!lstrcpyW","kind":"UnboundedCopy","reachable_from_input":true,"base_severity":"high","severity":"high","sources":["RegQueryValueExW"],"call_path":[{"va":"0x1400023a0","name":"NPInit"},{"va":"0x140002500","name":"sub_140002500"}],"limitation":"no value-level dataflow"}],
 "summary":{"risky_operations":31,"input_sources":9,"impactful":4}}
J
cat > "$OUT/callgraph.json" <<'J'
{"schema_version":"1.0","function_count":452,
 "processing_order":["0x140002500","0x140002418","0x1400023a0"],
 "reverse_topological_order":["0x140002500","0x140002418","0x1400023a0"]}
J
cat > "$OUT/functions/func_140002418.json" <<'J'
{"schema_version":"1.0","va":"0x140002418","name":"__isa_available_init","instruction_count":106,
 "block_count":20,"blocks":[],"cyclomatic_complexity":16,"information_score":22,
 "is_thunk":false,"is_library_code":false,"reachable_from_input":false,
 "api_calls":["ADVAPI32.dll!RegSetValueExW"],"referenced_strings":[]}
J
cat > "$OUT/functions/func_1400023a0.json" <<'J'
{"schema_version":"1.0","va":"0x1400023a0","name":"NPInit","instruction_count":61,
 "block_count":9,"blocks":[],"cyclomatic_complexity":7,"information_score":74,
 "is_thunk":false,"is_library_code":false,"reachable_from_input":true,
 "api_calls":["ADVAPI32.dll!RegSetValueExW","KERNEL32.dll!lstrcpyW"],
 "referenced_strings":["Software\\Microsoft\\Windows\\CurrentVersion\\Run"]}
J
cat > "$OUT/manifest.json" <<'J'
{"schema_version":"1.0","count":2,"functions":[
  {"va":"0x1400023a0","name":"NPInit","file":"functions/func_1400023a0.json","instruction_count":61,"block_count":9},
  {"va":"0x140002418","name":"__isa_available_init","file":"functions/func_140002418.json","instruction_count":106,"block_count":20}]}
J
echo "exported 452 functions to $OUT (65 thunks skipped)"
exit 0
