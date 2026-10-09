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

## Rounds 6–7 — continued novel-hunt (file-serving, config, protocol, security libs)

Swept ~90 more packages (Flask/Django extensions, config/deser loaders, scrapers,
protocol/HL7/ASN.1 parsers, auth/JWT libs) with the ReDoS oracle + high-severity scanner.
All candidates guarded, known, or not attacker-reachable:

| Target | Candidate | Verdict |
|--------|-----------|---------|
| `flask-admin` FileAdmin | `send_file` on user path | Guarded by `is_in_folder` (prefix-check weakness noted, impact limited to sibling dirs sharing the base prefix; likely known). |
| `Flask-AutoIndex` | `send_file(abspath)` | Guarded — `os.path.relpath`+`startswith('..')` blocks `../` and absolute escapes. |
| `omegaconf`, `confuse`, `python-box` | `yaml.load` | Safe — all use SafeLoader / SafeLoader subclasses. |
| `Flask-Session` 0.8 | `pickle.loads` fallback after msgpack/json | Latent RCE only with store-write access; maintainers already flag it (`TODO: remove in 1.0.0`). |
| `Flask-RESTful` `crypto.py` | `pickle.loads` | Dead utility, no callers, needs the key. |
| `hl7apy` | `load_message_profile(path)` → `pickle.load` | Caller-supplied path, offline-generated profiles; unsafe-by-design, not auto-reachable. |

Net: no additional *novel* finding in these rounds. The netmiko prompt-ReDoS cluster
remains the one genuinely undocumented, reportable vulnerability from the whole campaign
(~300+ packages across ReDoS, command injection, path traversal, deserialization, SSTI,
SSRF). The pandasai RCE is real but a known CVE.

## Round 8 — bug-bounty pivot (huntr / AI-ML) → SHAPASH RCE (novel)

Targeted huntr-eligible AI/ML tooling for RCE-class bugs. Flagship libs were hardened
(langchain loaders all gated behind `allow_dangerous_deserialization`; BentoML rejects
pickle on its external server; crewai pickles are local cache). Pivoted to the long tail
of ML tools with a **web surface**, and hit a genuine, novel finding:

**`shapash` 2.9.0 — unauthenticated RCE in the web dashboard.**
`shapash/webapp/smart_app.py:2997` runs `eval(button_id)` where
`button_id = ctx.triggered[0]["prop_id"].split(".")[0]` — and Dash's `prop_id` comes from the
client-supplied `changedPropIds` in the `/_dash-update-component` POST. A dot-free payload
(`getattr(__import__('os'),'system')('<cmd>')`) survives the `.split(".")[0]` and executes.
**Verified end-to-end** with a crafted Dash request (dash 2.18.2). Novel (no CVE found), fix is
a drop-in `json.loads`. See `advisories/shapash-dashboard-rce/`. This is the bug-bounty
candidate — submit via huntr / MAIF.

Also checked, not vulnerable / not bounty-worthy this round: langchain_community (gated),
bentoml (gated main server), crewai (local pickle cache), omegaconf/confuse/python-box
(SafeLoader), skops/m2cgen/sklearn2pmml (CLI, caller-supplied paths), hl7apy (offline profile).

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

## Round 9 — second huntr candidate: Taipy GUI query injection

Swept ML/LLM web apps (chainlit, taipy, mesop, solara, h2o, datasette, flaml, visidata,
pandasgui, holoviews …) for eval/exec/df.query/SSTI on request data. Finding:

**`taipy-gui` 3.0.0–4.0.2 (latest) — unauthenticated pandas `df.query` injection + ReDoS.**
`_PandasDataAccessor.__get_data` builds a `df.query()` string from the client `filters`
payload (delivered via the `DATA_UPDATE` WebSocket message); `action` and `col` are
interpolated raw, and `contains` feeds the client value to `.str.contains(<regex>)`. Demonstrated
filter bypass, blind data exfiltration, and ReDoS. Novel (no advisory for this sink); amplified
by Taipy's wildcard-CORS socket.io (CVE-2026-85183). RCE class per D-Tale CVE-2024-8862 but not
demonstrated (pandas grammar blocks lambdas here). See advisories/taipy-gui-query-injection/.

Others this round were by-design or local: FiftyOne `exec(custom_code)` is a warned power-user
feature; pandasgui/visidata are local desktop/TUI; datasette exec is plugin loading; h2o
eval/exec is internal codegen.

## Round 10 — model-file-format attempt (gguf): verified DoS, but KNOWN class (not submitted)

Targeted huntr's higher-paying model-file (MFV) track. Verified a real unbounded-allocation
DoS in the Python `gguf` package: `GGUFReader._get_field_parts` loops `range(alen[0])` on an
attacker-controlled uint64 array length; once reads pass EOF, `offs` stops advancing while the
loop keeps appending → a 49-byte crafted .gguf exhausts memory (reproduced: MemoryError under a
512MB cap).

NOT submitted — novelty check failed: the GGUF python-parser DoS space is already disclosed
(oss-sec advisory 2026-q2/546 explicitly names gguf_reader.py for alignment + n_dims unbounded
allocation; huntr has a public "GGUF vulnerabilities" hacking guide; CVE-2024-25665/66/67,
Ollama CVE-2025-66959/60, CVE-2026-7482). The array-length variant is at best a marginal
addition to that known class → duplicate risk. DoS-tier, not the RCE/$4K tier.

Takeaway: the model-file-format space (esp. GGUF) is heavily farmed, and its $4K RCE tier is
native-code memory corruption in llama.cpp/ggml — not verifiable in pure Python here and heavily
competed. The productive novel vein for this session remains ML *web apps* (shapash, taipy).

## Round 11 — third huntr candidate: Evidently collector arbitrary file write

Scanned web-framework files across the ~400-pkg corpus for eval/exec/query and file-path sinks.
Dead ends: mlflow scorer `exec` (guarded behind MLFLOW_SERVER_ENABLE_CUSTOM_SCORERS), llmware
`eval` (by-design caller DSL), chainlit FileResponse (guarded by is_path_inside), evidently UI
routes (litestar `:uuid` validated). Finding:

**`evidently` 0.7.23 — unauthenticated arbitrary file write in the collector service.**
`collector/app.py set_reference` writes `to_parquet(os.path.join(service_workspace, reference_path))`
where `reference_path` is a client-settable CollectorConfig field with no containment check
(absolute path discards workspace; `../` escapes). Unauthenticated by default: `run(secret=None)`
→ NoSecurityService.authenticate() always returns a user, so guards=[is_authenticated] passes.
Verified the path escape (absolute + traversal). Distinct from CVE-2026-75111 (UI read traversal);
this is a collector *write*. See advisories/evidently-collector-file-write/.
