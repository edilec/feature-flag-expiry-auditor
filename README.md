# Feature Flag Expiry Auditor

Offline, read-only audit of exported feature flags and a separately exported local-code reference index. It never edits, disables, or deletes a flag or source file. Node.js 22+, zero dependencies. `src/index.mjs` exports `auditFlags(flagsDoc, referencesDoc, policy, {now, deadline})` and `TOOL_ID`.

```sh
node bin/feature-flag-expiry-auditor.mjs --root examples --policy policy.json --flags passing-flags.json --references references.json
node bin/feature-flag-expiry-auditor.mjs --root examples --policy policy.json --flags failing-flags.json --references references.json
```

The synthetic examples exit 0 and 1. `--help` prints usage to stderr; a bounded human summary goes to stderr on normal runs. Stdout is exclusively the v1 JSON report.

Policy: `{"schemaVersion":"1","asOf":"2026-09-26T00:00:00Z","staleAfterDays":30}`. Flags: `{"schemaVersion":"1","complete":true,"flags":[{"key":"synthetic-flag","owner":"team-a","expiresAt":"2026-10-01T00:00:00Z","variants":[{"name":"on","lastUsedAt":"2026-09-25T00:00:00Z"}],"cleanupDependencies":["code-callers"]}]}`. References: `{"schemaVersion":"1","complete":true,"references":[{"flagKey":"synthetic-flag","file":"src/flags.mjs","line":12}]}`. Both complete assertions are required. The reference file and line identify the operator's exported source index; the checker does not scan a repository itself. Variant usage older than `asOf - staleAfterDays` is stale. Expiry at or before `asOf` is expired. Cleanup dependency names must be explicit and nonempty. Reference paths are relative and validated, but are never opened or emitted.

| Rule ID | Severity | Meaning |
| --- | --- | --- |
| policy-invalid | warning | invalid policy (CLI rejects configuration) |
| flags-invalid | warning | flag export shape/identity invalid |
| references-invalid | warning | reference export shape/position invalid |
| export-incomplete | warning | either export declares partial coverage |
| variant-unknown | warning | variant usage absent, invalid, or future-dated |
| reference-unknown | warning | code reference lacks matching exported flag |
| limit-exceeded | warning | byte, count, depth, or time bound exceeded |
| input-unreadable | warning | export cannot be read/decoded/parsed |
| owner-missing | error | flag owner blank or unusable |
| flag-expired | error | expired flag without indexed references |
| expired-flag-referenced | error | expired flag still referenced at indexed ordinal |
| variant-stale | error | variant usage before freshness cutoff |
| cleanup-undocumented | error | no usable cleanup dependency names |

Reports sort findings by code unit `(location.file, location.pointer, ruleId)`. `@flags`, `@references`, and `@policy` are fixed logical source roles, not host paths; pointers include zero-based flag/variant/reference ordinals to locate the record in the exact invoked file. No flag names, paths, owners, or source text are copied to output. Exit 0 pass; 1 policy failure; 2 incomplete evidence/configuration. Invalid usage, root, path, or policy leaves stdout empty; unreadable or ambiguous flag/reference input emits an incomplete report. Every file is read-only and realpath-confined beneath the declared root.

Limits: each export ≤1 MiB; policy ≤64 KiB; ≤1000 flags, ≤10000 references, ≤5000 variants; JSON depth ≤16; injected deadline 5 seconds. UTF-8 is strict; duplicate JSON object keys, including escaped aliases, are refused. A bound breach is incomplete, never truncated. The tool cannot prove that a code-reference export covers every source language, dynamic flag access, or runtime flag state; validate the export's coverage independently. Run `npm run check` for syntax and tests.
