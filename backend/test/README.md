# backend tests

Two things, both aimed at the failure mode a status-code check misses: a route
that answers `200` with the wrong shape.

## `contract.mjs`

Replays exactly what `App.tsx`'s `loadRun` does — `image`, `functions`,
`findings`, `strings` in parallel — then asserts that every field the UI
components actually read is present, with the right type. Addresses must be hex
*strings*, string encodings must be `ascii` or `utf16`, `findings.summary` must
carry `impactful` and `risky_operations`, and the explanation URL built from
`finding.function` + `finding.api` must be routable.

```
node test/contract.mjs http://localhost:3000/api <run_id>
```

Exits non-zero on any mismatch, so it works in a script.

## `fake-engine.sh`

Stands in for `sp.exe`. Emits the same stderr lines the real engine emits — same
`[info] ` prefix, same wording — with delays between them, then writes a minimal
but schema-correct set of output files.

This exists because the progress bar is driven by parsing the engine's log
messages. Testing that parser against a fixture that copies the real message
shapes catches a reworded log line; testing it against the parser's own
assumptions catches nothing.

```
chmod +x test/fake-engine.sh
SP_BINARY=$PWD/test/fake-engine.sh DATA_DIR=/tmp/spdata PORT=3130 node server.js
```

Then upload anything — the file contents are ignored — and watch
`GET /api/runs/<id>/status` walk through every stage.

Requires bash, so on Windows use WSL or Git Bash. Against the real `sp.exe` none
of this is needed; it is for exercising the backend without a build.
