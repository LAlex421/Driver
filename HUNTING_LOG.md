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

## Round 2 — command-injection + wider ReDoS sweep (~175 packages)

Built an AST taint scanner (`scripts/taint_scan.py`) for command-injection, and a
method-aware automated ReDoS oracle (`scripts/auto_redos2.py`) validated against the
known configobj bug. Swept ~175 packages.

| Target | Finding | Verdict |
|--------|---------|---------|
| `netmiko` 4.8.0 | `set_base_prompt` prompt regex `\*?(.*?)(>.*)*#` (nokia_sros.py:67, nokia_isam.py:25) | **REAL — exponential ReDoS, novel.** ~26-byte device prompt hangs host >10s. Device-controlled input. No CVE found. See `advisories/netmiko-nokia-redos/`. |
| `markdown2` 2.5.5 | `_key_val_list_pat` (line 621) | **False positive** — blows up only under `fullmatch`; real call is `re.findall` (linear). Oracle over-flagged `compile`-site patterns. |
| `pyttsx3` 2.99 | `os.system(f"aplay {temp_wav_name}")` | **False positive** — temp name is a random `NamedTemporaryFile`; text goes via C API, not shell. |
| `command_runner`, `invoke`, `cmd2`, `pyinfra` | `shell=True` / `os.system` | By design (command-runner libraries). Not vulns. |

## Round 3 — continued sweep (~230 packages total)

Swept templating/serialization/HTTP/markup/validation packages across CMDI, path
traversal, XXE, unsafe deserialization, and ReDoS. No new confirmed vulnerability;
several candidates investigated and disproved:

| Target | Candidate | Verdict |
|--------|-----------|---------|
| `trafilatura`, `premailer` | XML parse of remote/attacker content | Safe — `resolve_entities=False`, `no_network=True`. |
| `genshi` | `ExternalEntityRefHandler` + `XML_PARAM_ENTITY_PARSING_ALWAYS` | Safe — handler ignores the external `sysid` and substitutes genshi's own internal HTML-entity DTD; no file/network fetch. |
| `pooch` | remote tar extraction | Guarded (`filter=` kwarg); zip paths stdlib-sanitised. |
| `bbcode` | `_url_re` URL-linkification regex (`(?:[^\s()<>]+|\(...\))+`, used with `.search`) | False positive — input that reaches it is all-matching, so the match succeeds with no forced-failure backtracking. Linear to n=40+. |
| `pygments`, `mwparserfromhell`, `markdown`, `werkzeug` | lexer/parse regexes | No nested-quantifier ReDoS surfaced. |
| `netmiko` bulk-encrypt `yaml.load(f)` | unsafe YAML | Low — local CLI reading operator's own config; modern PyYAML uses FullLoader (no arbitrary exec). |

Net result of rounds 2–3: one strong, novel finding (**netmiko Nokia ReDoS**, see
`advisories/`). Everything else was guarded, low-threat, or a disproved false positive —
the expected hit rate for auditing maintained packages.

## Round 4 — deep audit of one target (netmiko)

AST-extracted and battery-tested **all 178** `re.*` call sites in netmiko 4.8.0
(`scripts/netmiko_audit.py`), each under its real method. Also reviewed the non-ReDoS
surface (ProxyCommand = ssh-config-driven, not remote; SCP commands are device-side with
caller-controlled paths → clean).

Result: a **cluster of four prompt-parsing ReDoS sites**, all in per-driver
`set_base_prompt()` overrides running `re.search` on device-controlled prompt text:

| Site | Regex | Growth |
|------|-------|--------|
| `nokia/nokia_sros.py:67` | `\*?(.*?)(>.*)*#` | exponential (~26 B → >10s) |
| `nokia/nokia_isam.py:25` | `\*?(.*?)(>.*)*#` | exponential |
| `extreme/extreme_exos.py:41` | `[\*\s]*(.*)\.\d+` | polynomial ~O(n³) (2 KB → >12s) |
| `cisco/cisco_asa_ssh.py:116` | `(.*)\(conf.*` | polynomial ~O(n²) (20 KB → >8s) |

Shared root cause and fixes verified behaviour-preserving + linear — see
`advisories/netmiko-prompt-redos/`. The deep-dive turned a single bug into a documented
*class*, which makes for one coherent, higher-value disclosure.

Extra false-positive caught here: the oracle flagged a regex under `fullmatch` that netmiko
actually runs with `re.search`; and a naive "fix" that kept a leading `[\*\s]*` was still
O(n²) because `re.search` re-scans from every offset — the real fix must **anchor** (`^`).

## Round 5 — "stronger target" pivot: AI/ML + web (RCE/path/deser/SSTI)

Moved up the severity ladder to RCE-class sinks in bounty-hot AI/ML tooling
(`scripts/hisev_scan.py`). Results:

| Target | Candidate | Verdict |
|--------|-----------|---------|
| `txtai` 9.14 | Jinja `from_string` in LLM agent; `pickle` index loader | Safe — `SandboxedEnvironment`; pickle gated behind explicit `ALLOW_PICKLE` (raises by default). |
| `flask_swagger_ui`, `Flask-Uploads` | `send_from_directory(user_path)` | Safe — werkzeug `safe_join` blocks traversal on modern Flask. |
| `gradio_client`, `kedro`, `llama_index_core`, `guardrails_ai`, `marvin`, `instructor` | `eval`/`exec`/deser | Only in examples/CLI or developer-controlled paths; nothing attacker-reachable. |
| **`pandasai` 2.3.2** | `exec()` of LLM-generated code behind a custom `_clean_code` sandbox | **RCE — fully reproduced**, BUT a **known CVE** (CVE-2024-12366, ≤2.4.3). Not novel. See `advisories/pandasai-sandbox-escape/`. |

The pandasai escape is real and end-to-end (string-split `getattr` defeats the substring
`_is_jailbreak` filter; `__globals__` gadget reaches `os`). Prior-art check turned it from
"a new RCE" into "a reproduction" — the honest outcome. Key lesson: **a higher-severity
target yields a higher-severity bug class, but severity ≠ novelty.** The only *novel*
reportable finding from all rounds remains the netmiko prompt-ReDoS cluster.

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
