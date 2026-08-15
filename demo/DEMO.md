# Demonstration guide

A purpose-built target for showing the tool working. Every number below was
produced by actually running it, so if you see something different, something
has changed.

## What is in this folder

| File | What it is |
|---|---|
| `demo_target.c` | The source. Heavily commented, and the thing to put beside the decompiled output. |
| `demo_target.exe` | The weak build. Every mitigation off, one W^X section, bad checksum. **This is the file to analyse.** |
| `demo_target_hardened.exe` | Produced by `sp harden`. ASLR + DEP on, checksum fixed, W^X left alone. |
| `demo_target_hardened_wx.exe` | Same, plus `--fix-wx`, so W^X is removed too. |
| `harden_report.json`, `harden_report_wx.json` | The tool's own output for both. |
| `demo_config.txt` | Normal input — applies a setting. |
| `config_launch.txt` | Starts Notepad. |
| `config_registry.txt` | Writes to the registry. |
| `config_overflow.txt` | 200 bytes into a 64-byte buffer. **Crashes on purpose.** |
| `build_demo.bat` | Rebuilds it, with every linker flag explained. |

All three executables run. The hardened ones behave identically to the weak one.

## The five-minute script

### 1. Show the program does something ordinary

```
demo_target.exe demo_config.txt
```

Reads a config file, prints a checksum, applies a setting. 141 functions —
small enough to hold in your head, real enough to be interesting.

### 2. Analyse it, and show the headline finding

Upload `demo_target.exe`. Expect:

```
141 functions, 2937 instructions, 461 blocks
1 input source, 8 risky operations, 8 reachable from untrusted input
```

The finding to open is the **HIGH** one:

```
unbounded-copy   HIGH   5 hops
load_and_apply_config > parse_directive > apply_directive > copy_setting > strcpy
```

This is the point of the whole project. Say it in two parts:

- The engine rated it High because an unbounded copy is serious **and** because
  a path from untrusted input reaches it. An identical `strcpy` nothing could
  reach is downgraded, not dropped.
- The path is evidence, not a claim. Every hop is a real call edge, and you can
  click into any of them.

### 3. Prove the defect is real

```
demo_target.exe config_overflow.txt
```

It aborts with `0xC0000409` — `STATUS_STACK_BUFFER_OVERRUN`. The stack cookie
caught it. Two things worth saying: the finding was not theoretical, and `/GS`
is a mitigation the hardener explicitly refuses to claim it can add, because
cookies are compiler-emitted code rather than a header bit.

### 4. Compare source against decompiled C

Open `compute_checksum` at **`0x140001580`** and **Lift with AI**, then put it
beside the source:

```c
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
```

This is the best function to compare, and here is the specific thing to look
for. At `/Od` the compiler did **not** emit a `rol` instruction. It emitted the
three-instruction rotate idiom, which you can show in the disassembly pane
beside the C:

```
mov eax, dword ptr [rsp]
shl eax, 3            ; sum << 3
mov ecx, dword ptr [rsp]
shr ecx, 0x1d         ; sum >> 29
or  eax, ecx          ; ...ored together: a rotate left by 3
```

So the question to ask out loud is: **did the model recognise that as a
rotation, or reproduce it literally as two shifts and an or?** Either answer is
a good answer — one shows idiom recognition, the other shows the model staying
faithful to the instructions rather than guessing. What matters is that you can
check, because the source is right there.

The function has 5 basic blocks and a real back edge, so it also exercises loop
recovery. The coverage figure under the output is measured from block tags in
the generated C, not reported by the model.

Good second choices: `apply_directive` at `0x140001480` (branch structure) and
`load_and_apply_config` at `0x140001a00` (the API sequence).

### 5. Security tab — before and after

`demo_target.exe` starts with everything off:

| | ASLR | DEP | CFG | W^X section | Checksum |
|---|---|---|---|---|---|
| `demo_target.exe` | ✗ | ✗ | ✗ | `.data` | invalid |
| `demo_target_hardened.exe` | ✓ | ✓ | ✗ | `.data` | fixed |
| `demo_target_hardened_wx.exe` | ✓ | ✓ | ✗ | none | fixed |

The **refused** list is the part to dwell on, because it is where the tool
declines to overstate itself:

- **Control Flow Guard** — cannot be added. The flag without the compiler's
  guard tables would be a lie in the header.
- **W^X** — reported by default, only removed with `--fix-wx`. A packer or
  self-modifying code legitimately needs a writable, executable section, and
  silently breaking such a binary is worse than reporting the risk.
- **`/GS` and CET** — not representable in the header at all. Rebuild required.

That is three separate refusals, each with a reason. It is a stronger
demonstration than three more ticks would have been.

### 6. If asked what it cannot do

Two limitations are built into this demo on purpose, and both are worth
volunteering before someone finds them.

**Jump tables.** `apply_directive` is an if/else chain, not a `switch`.
A dense switch compiles to a jump table — an indirect jump the disassembler
cannot statically resolve — so the case bodies fall outside the function's
recovered CFG, the calls inside them are never attributed to it, and all eight
findings become *unreachable* even though the program plainly reaches them.
Rewriting it as if/else produced the reachable paths above. Same program, same
behaviour, completely different analysis. That is the honest limit of static
control-flow recovery.

**Import-based classification.** This is built with `/MD`, so the C runtime is
imported and `strcpy` appears in the import table where it can be classified.
Rebuild with `/MT` and the CRT is linked in, `strcpy` has no import entry, and
the High-severity finding vanishes entirely. If there is time, show it — it is
a real limit of classifying by imported name, not a defect.

## Command-line version, if the web app misbehaves

```
sp.exe findings     demo\demo_target.exe
sp.exe mitigations  demo\demo_target.exe
sp.exe harden       demo\demo_target.exe --out demo\hardened.exe
sp.exe harden       demo\demo_target.exe --out demo\hardened_wx.exe --fix-wx
sp.exe functions    demo\demo_target.exe
sp.exe disasm       demo\demo_target.exe --at 0x140001a00
```

Addresses in this build — they change if you rebuild:

| Address | Function |
|---|---|
| `0x140001a00` | `load_and_apply_config` — the input source, head of every call path |
| `0x1400013f0` | `parse_directive` |
| `0x140001480` | `apply_directive` |
| `0x140001520` | `copy_setting` — the overflow |
| `0x140001580` | `compute_checksum` — the loop, best for comparison |
| `0x140001600` | `launch_helper` |
| `0x140001750` | `load_plugin` |
| `0x1400017f0` | `make_page_writable` |
| `0x140001870` | `record_run` |
| `0x140001930` | `write_log` |
