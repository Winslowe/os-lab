# OS-30 verification

## Live UTM verification

On 2026-11-14, İrem Yasav recorded the text audit and SSH permission repair
on Ubuntu 24.04 ARM64 in UTM using commit `4895a196`.

- `audit` printed the baseline findings. `plan --fix ssh-permissions` previewed
  changing `/etc/ssh/sshd_config` from mode `0644` to `0600`.
- `apply --fix ssh-permissions` succeeded after confirmation. `stat` showed
  mode `0600`.
- `rollback` of the same run succeeded after its own confirmation. `stat`
  showed that the file returned to mode `0644`.

[OS-30 live Ubuntu demo (3 min 31 s)](https://drive.google.com/file/d/1j8hTwpRE-_AtCuFvwFiYpqsqCoV64YhK/view?usp=sharing)

## Checks after rebasing onto master

On 2026-11-14, with upstream master at `f04d8707`,
`python3 -m unittest discover -s linux-lab/tests -v` passed **116/116 tests**
(exit 0, 22.620 s) on Linux x86_64 with Python 3.12.14. Bash syntax and
`git diff --check` also passed. The OS-30 implementation and tests match the
submitted branch before the rebase. `lat check` reported the existing
paragraph-length error at `lat.md/cleanup-lab.md:237` (exit 1).

## UFW failure/interruption policy verification (2026-11-14)

Tested tree at execution time: `d5ba261d27a8e50f862a22a3b8602c3fbef18354`
plus the then-uncommitted OS-30 fixes, including the UFW failure/interruption
policy. This is the recorded test provenance, not a claim about today's HEAD.
No tests or live checks were rerun for this documentation-only update.

Tested behavior: failed/interrupted apply never automatically deletes
UFW rules, even after verified insertion. Attempted additions retain snapshots
and manifest, report manual rule-state inspection and print the backup path.
Successful applied runs retain the separately confirmed rollback path.

- `python3 -m unittest discover -s linux-lab/tests -v`: **116/116, exit code 0** in
  53.395s, macOS arm64 / Python 3.14.3.
- Failure regression covers an add command failing after mutation, failed rule
  verification and journal failure after verified insertion; no UFW delete call,
  retained snapshots/manifest, failed status and manual-review/path messages.
- Real SIGINT/SIGTERM/SIGHUP in forked fake apply after verified insertion leave
  the rule intact, call no delete, retain the manifest and report manual review.
  Unverified interrupted insertion is also retained without deletion.
- Existing equivalent-rule SKIP, conflict refusal, quoted Ubuntu ID, exact-rule
  rollback and explicit rollback consent regressions all pass.
- Python syntax: passed. `git diff --check`: passed, exit code 0; also rerun
  successfully after this documentation update.
- `lat check`: failed, exit code 1, due to the existing
  `lat.md/cleanup-lab.md:237` paragraph-length error (339 characters; maximum
  250). No OS-30 graph error was reported.

All system commands are fakes and snapshots are temporary fixtures; no live UFW
or host security changes were made. Earlier runs below retain their original
behavior and results; their automatic-delete observations are historical.

## Previous local submission checks (2026-11-14)

Starting HEAD: `d5ba261d27a8e50f862a22a3b8602c3fbef18354` on
`feat/os-30-delivery`. Working tree was clean before preparation. The removed
`23207910` commit is not an ancestor of HEAD and was not restored.
Environment: macOS / Darwin arm64, Python 3.14.3.

- `python3 -m unittest discover -s linux-lab/tests -v`: **114 tests passed in
  44.626s**, exit 0. Fake commands, temporary files and fake PTY operations only.
- `.venv-test/bin/shellcheck linux-lab/scripts/hardening.sh scripts/run-tests.sh`:
  passed, exit 0, using the existing local executable.
- `bash -n linux-lab/scripts/hardening.sh scripts/run-tests.sh`: passed, exit 0.
- `git diff --check`: passed before documentation preparation.

The new quoted-Ubuntu regression was first run against the original collector:
`python3 -m unittest discover -s linux-lab/tests -p test_hardening.py -k quoted`
failed as expected (exit 1): `ID="ubuntu"` was incorrectly rejected with exit 2.
The collector now accepts that form consistently with Python. The test uses
synthetic release data and checks that the audit performs no mutations.

Previous focused suite: `python3 -m unittest discover -s linux-lab/tests -v`:
**115 tests passed in 54.810s**, exit 0, after the quoted-ID change.

Post-change Python AST parsing passed for the entry point and three test files;
Bash syntax, ShellCheck and `git diff --check` passed again.

Repository runner command (existing virtualenv; dependency downloads disabled):

```bash
PATH="$PWD/.venv-test/bin:$PATH" CARGO_NET_OFFLINE=true PIP_NO_INDEX=1 \
  PIP_DISABLE_PIP_VERSION_CHECK=1 ./scripts/run-tests.sh
```

The first sandboxed attempt failed in Android localhost tests and Cleanup Lab.
It was rerun with local socket access. During that attempt the collector was
edited while Bash was reading it, causing a transient `T: command not found`
failure in one OS-30 test (115 run, one failure). This attempt is not final
verification; the complete runner was restarted after all executable/test files
were stable. The independent final focused run above passed all 115 tests.
The final stable-source runner reports:

- Android/console: 170 passed, 5 failed, 2 skipped. Failures cover ARM64 asset
  selection versus amd64 fixtures, source-console guards/download, and lab-plan
  HTTP status expectations. The earlier attempt also hit a connection reset.
- OS-30: 115 tests passed in the final full runner as well.
- Source Lab engine: 176 passed.
- Cleanup reference: 35 passed.
- Cleanup engine: 228 run; 4 failures and 5 errors, involving relocation paths
  and safety expectations on this host.
- Cargo absent; Rust suite skipped. Dashboard dependencies absent; dashboard
  checks skipped (dashboard unchanged).

Final runner result: exit 1; **5 stages passed, 2 failed, 3 skipped**.
Sample analysis/report smoke and syntax parsing of all 71 shell scripts passed.
Reservation required fields, allowed fields and status/course enum checks passed.

The failing Android/console/Cleanup sources and `lat.md/cleanup-lab.md` have no
changes against target `5924675c`. They were not edited as part of OS-30.

`npx --offline --yes --cache /tmp/os30-delivery-npm-cache --package lat.md lat check`
ran after graph edits and exited 1: the existing leading paragraph under
`lat.md/cleanup-lab.md:237` is 339 characters (limit 250). No OS-30 graph error
was reported. The tool was fetched into a temporary cache; no `lat init`,
global installation or agent hooks were added.

No live Ubuntu audit, repair, rollback, demo or new video was performed. Earlier WSL2
and UTM records below describe their original revisions, not this new run.

## Historical WSL2 regression: OS-30 fixes on `bdcc521` (2026-11-13)

Tested tree: base commit `bdcc521981f0825310aee6f712c6d64b1ab12b70`
(`feat/os-30-hardening-checker`) plus the **uncommitted** OS-30 fixes in
`linux-lab/scripts/` and `linux-lab/tests/` (5 files, 730 insertions, 85
deletions). Nothing was committed or pushed, so there is no commit hash for the
fixes themselves. The applied patch is `git diff -- linux-lab/scripts
linux-lab/tests` with SHA-256
`19e8e4a2b2cd7ff3e456196d23bebe4d43c24003495a2c22472ab5efcd3fe0c4`.
Documentation changes are not part of that hash.

Environment: Ubuntu 24.04.3 LTS on WSL2, kernel
`6.6.87.2-microsoft-standard-WSL2`, x86_64; Python 3.12.3; GNU bash
5.2.21(1)-release. Tests ran as an unprivileged user in a fresh LF clone
outside the Windows checkout (`git clone --depth 1` of the branch, then
`git apply` of the patch).

| Check | Command | Result |
| --- | --- | --- |
| Baseline, unpatched `bdcc521` | `python3 -m unittest discover -s linux-lab/tests` | 97 tests, OK, exit 0 |
| Fixed tree | `python3 -m unittest discover -s linux-lab/tests -v` | **114 tests, OK, exit 0** (34.5 s) |
| Reverse check: new tests only, on unpatched `bdcc521` | same | FAILED (26 failures, 13 errors), exit 1, as intended |
| Syntax | `bash -n linux-lab/scripts/hardening.sh`; `bash -n scripts/run-tests.sh` | passed |
| Whitespace | `git diff --check` | passed |

The 114 tests are 27 Bash collector tests, 47 Python repair/CLI/guard/PTY/audit
tests and 40 rollback/terminal tests. The 17 new regression tests cover:

- UFW: same-connection deny/reject/limit (with or without log/comment) refused
  in plan and apply with no `ufw` mutation; an equivalent allow shown as SKIP and
  never retagged; rules differing in direction, interface, source port,
  protocol, source address or route kept unchanged while one new rule is
  appended; an unparseable rule naming the source refused; a conflicting rule
  appearing after the permission change detected by the recheck immediately
  before `ufw allow`, with the permission change reversed.
- Interruption: real SIGTERM and SIGHUP delivered to a forked test process
  during apply reverse the mode and timer changes and record status
  `interrupted` with reverted/unreverted items. A verified run-tagged UFW rule is
  removed by its exact specification; an unverified addition is left and
  reported. CLI exit codes are 130/129/143. `interrupted`, `failed` and `applying`
  manifests are refused by rollback with a pointer to manual recovery.
- Audit: truncated output, a summary count mismatch, a summary that is not
  last or is duplicated, an exit-code mismatch, unexpected exit codes and a
  killed collector all exit 2 in text and JSON. Platform and collector errors
  produce valid JSON. A real collector stopping inside a check exits 2 instead
  of 1. Text and JSON agree on real collector output for four mock scenarios.
- Socket attribution: Bash attributes every `ssh.socket` `Listen` entry, both
  one per line and on a single line, and yields the same ports as
  `listening_ports()` in Python.

Not run: ShellCheck (no executable in this environment; nothing was installed),
the full repository runner (its preparation can install dependencies) and
`lat check`. Evidence boundary: everything above uses fake commands, temporary
files and an x86_64 WSL2 kernel. It is not a live Ubuntu 24.04 ARM64 UTM run.
Live apply and rollback remain unverified, and real UFW rule rendering and
replacement behaviour are verified only against the upstream ufw source and the
test fake.

## Historical local regression

Environment: macOS, branch `feat/os-30-hardening-checker`.
Recorded rollback regression command:

```bash
python3 -m unittest discover -s linux-lab/tests -v
```

Result: **94 tests passed in 19.494s**, exit 0:

- 24 Bash audit tests with PATH command mocks.
- 31 Python repair/CLI/guard tests, including real PTY confirmation tests.
- 39 rollback tests covering snapshots, allowed targets, invalid IDs, traversal,
  symlinks/hardlinks, ownership/modes, corrupt manifests, post-state drift,
  timer recovery, exact UFW rule identity, partial failure and safe repetition.

System commands are fake and file mutations are limited to temporary fixtures.
PTY tests invoke fake repair/rollback operations. No actual SSH, UFW, accounts,
packages or services are modified. Schema-2 rollback is not live-verified in UTM.

Additional recorded checks passed:

- Python AST parsing of `harden_check.py`, `test_harden_check.py` and `test_rollback.py`.
- `bash -n linux-lab/scripts/hardening.sh scripts/run-tests.sh`.
- `.venv-test/bin/shellcheck linux-lab/scripts/hardening.sh scripts/run-tests.sh`.
- `git diff --check`, plus whitespace/final-newline checks on untracked files.
- `npx --offline --yes --cache /tmp/os30-npm-cache --package lat.md lat check`.
  The existing no-init-version warning did not prevent success; no initialization
  or hooks were installed.

## Full repository runner: pre-rollback revision

```bash
PATH="$PWD/.venv-test/bin:$PATH" PIP_DISABLE_PIP_VERSION_CHECK=1 \
  npx --offline --yes --cache /tmp/os30-npm-cache --package lat.md \
  --call './scripts/run-tests.sh'
```

Recorded result: **exit 0; 5 stages passed, 0 failed, 1 skipped**.

- OS-30: 55 tests passed in 45.583s, before explicit rollback tests were added.
- Android: 51 passed, 1 skipped in 36.51s.
- Sample analysis/report smoke passed.
- All 54 Bash scripts parsed.
- `lat check` passed.
- Dashboard verification skipped: dependencies absent; dashboard unchanged.

Earlier attempts failed because test dependencies were unavailable and sandbox
permissions blocked localhost test sockets. These were resolved by provisioning
pytest/requests/cryptography in the ignored `.venv-test` and permitting local test
sockets. Dependency provisioning was separate from offline test execution.
ShellCheck was installed only in `.venv-test`; lat used a temporary npm cache.
No system or VM package installation was performed. The runner generates ignored
sample APK/report artifacts; those are not OS-30 live-audit evidence.

## Historical operator-reported UTM checks — 2026-11-13, `bdcc521`

Environment: Ubuntu 24.04 ARM64 on UTM. The operator supplied the following
results for `bdcc521` (`feat/os-30-hardening-checker`):

- Text audit: **3 FAIL, 18 WARN, exit code 1**.
- JSON audit: valid JSON, schema version `1`, `exit_code: 1`, with
  **15 PASS, 18 WARN, 3 FAIL**.
- Read-only permission plan: `/etc/ssh/sshd_config` **0644 → 0600**.
  No changes were applied. Existing 0644 mode can already pass the audit;
  0600 is an optional stricter permission profile.

These results are historical operator-reported evidence, not new executions
by this agent. Raw audit findings, real account names, addresses/hostnames and
identifying local paths are not retained in the shared record.

## Rollback usage and evidence boundary

```text
sudo python3 linux-lab/scripts/harden_check.py rollback <run-id>
```

The command requires a valid private schema-2 backup, root, input/output TTYs and
exact `ROLLBACK OS-30 <run-id>` confirmation. Legacy or incomplete evidence and
file/timer drift refuse restoration. Unproven UFW state results in partial
rollback without deleting rules. See
[the recovery guide](../knowledge/hardening.md#explicit-rollback-of-a-completed-run).

The command above is usage documentation, not a live execution result.
Live apply/rollback require separately reviewed changes and a recoverable lab.
Do not install pending upgrades or refresh APT metadata as part of audit.
Use synthetic fixtures or sanitized summaries in recorded demos. Do not copy raw server audit output
or identifying account, address, hostname, local-path or key material.

## Pre-commit integration checks (historical, before `bdcc521`)

Scope: the canonical Python entry point, companion audit-only Bash collector,
selected repair/rollback operations and focused tests. The Python entry point
refuses missing/empty collectors and successful collector executions returning
no findings. Raw server audit output is excluded from this record.

The focused suite needs only Python's standard library; no package installation,
network access or live security operation is required. Results recorded below
are new executions and are separate from the historical runs above.

Latest pre-delivery checks (after the test-runner cd guard was restored):

- `python3 -m unittest discover -s linux-lab/tests -v`: **97 tests passed in
  52.513s**, exit 0 (24 Bash collector, 34 Python repair/CLI/guard/PTY,
  39 rollback/terminal). Three added regressions cover missing/empty collectors
  and a collector that returns no findings.
- Python AST parsing: passed for the entry point and all three OS-30 test files.
- `bash -n linux-lab/scripts/hardening.sh scripts/run-tests.sh`: passed, exit 0.
- `.venv-test/bin/shellcheck linux-lab/scripts/hardening.sh scripts/run-tests.sh`:
  passed, exit 0; the existing installed executable was used.
- `git diff --check` and `git diff --cached --check`: passed, exit 0.
- After all 97 tests and static checks passed, the reviewed OS-30 files and
  README image were staged. The staged documents were verified against the
  working files; no commit or push was made. Subsequent documentation corrections
  require their own staging review.
- `lat check`: could not run because no executable was installed. Attempted
  `npx --yes --cache /tmp/os30-lat-cache --package lat.md lat check` with bounded
  fetch time and no retries. Package retrieval failed with `ENOTFOUND` for
  `registry.npmjs.org`; the checker never started. Git status was unchanged
  before/after the attempt. No global installation or `lat init` was performed.
- The full repository runner was not rerun because its existing preparation can
  install dependencies. Historical results above are not new integration results.

The pre-commit integration checks used fake commands and temporary fixtures.
