# Hunting log — ReDoS pass over PyPI parsers

A running, honest record of what was examined, what held up, and what didn't. The
false positives are the point: rigor is what separates a real finding from noise.

## Method

1. Downloaded sources of ~90 small/active PyPI packages (sdists only, read as text —
   never executed).
2. Ran a static "dangerous-shape" scanner (`scripts/redos_scan.py`) to flag nested /
   overlapping quantifiers in regex **literals** passed to `re.*`.
3. **Timed** each candidate against crafted adversarial input, growing input size to see
   whether match time is linear or super-linear.
4. For any super-linear hit, confirmed (a) reachability from a realistic source, (b) how
   the regex is actually invoked (`.match` vs `.search`, anchored or not), and (c) prior art.

## Findings

| Target | Regex | Verdict | Why |
|--------|-------|---------|-----|
| `configobj` 5.0.9 | `_sectionmarker` | **Real ReDoS (≈cubic)** | Confirmed via public API; see `ADVISORY.md`. Already reported upstream as issue #281 — credited, not claimed. |
| `docutils` 0.23 | `simple_table_top_pat = '=+( +=+)+ *$'` | **False positive** | Blow-up only under `re.search`; docutils invokes it via the state machine's default `pattern.match()` (anchored). Disjoint char classes → linear under `.match`. |
| `mistune` 3.3.4 | `_directive_re` (rst / fenced) | **False positive** | Pattern ends unanchored (`(?:…\n+)*`) and is used with `.match`, which only needs a prefix match — no forced failure to drive backtracking. Linear at 25 KB input. Also opt-in (non-default plugin). |
| `markdown2`, `humanfriendly`, `validators`, `img2pdf`, `w3lib`, `parse`, … | various | Not confirmed | Flagged by shape heuristic; timed out linear, or not reachable from attacker input. |

## Lessons (the traps)

1. **`re.search` fakes quadratics.** Searching retries at every start offset, so *any*
   pattern looks O(n²) on a non-matching string. Always test with the same method the
   victim code uses. Check the call site before believing a timing graph.
2. **No trailing anchor, often no ReDoS.** Catastrophic backtracking needs a *forced
   failure* after the ambiguous part. An unanchored pattern used with `.match` can usually
   satisfy itself with a prefix and bail out early — no explosion.
3. **Reachability and defaults matter.** A bug behind an opt-in plugin, or only reachable
   from developer-controlled (not attacker-controlled) input, is a much weaker report.
4. **Check prior art before claiming.** The one real bug here was already filed upstream.
   Rediscovery is fine; misrepresenting it as original is not.
