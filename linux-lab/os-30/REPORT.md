# OS-30 delivery report

## Submission

The MYO203 submission is [PR #194](https://github.com/keyvanarasteh/os-lab/pull/194).
The [verification record](VERIFY.md#live-utm-verification) links to the live
Ubuntu recording and documents the SSH permission repair and rollback.

## Historical local submission review (2026-11-14)

Prepared for owner review on `feat/os-30-delivery`; intended PR target:
`keyvanarasteh/os-lab:master`. No commit, push, PR, live demo or new video was
made during this preparation. The removed `23207910` commit was not restored.
Starting HEAD is `d5ba261d27a8e50f862a22a3b8602c3fbef18354`.

The target fetched on this date is
`5924675c2edce5f88dbf68b46f3504d8dba2a051`: HEAD is three commits ahead,
zero behind, with no merge conflict against that target. Before preparation,
the 12 changed files covered OS-30 code, mock tests, documentation/image and test-runner integration.
The local reservation recorded MYO203 (the repository's Open Source OS
course mapping) and `in-progress` at that stage.

The full course `vize/vize-projesi.md` is not present in this checkout and was
not located through accessible searches. The available
[student reservation instructions](../../reservations/README.md#students-midterm)
require verification and a proof video.

AI assistance: Codex inspected repository history, code and documentation, ran
local mock/static checks and the repository runner, fixed quoted Ubuntu ID
detection with a regression test, and updated submission records and reservation
metadata. The student must review the changes and understand the implementation before submission.

## Preparation changes

- Fixed Bash platform detection for double-quoted `ID="ubuntu"`, consistent
  with the Python entry point. The new read-only regression fails on the original
  collector and passes with the fix. The mock now evaluates the actual grep
  expression against synthetic os-release data rather than assuming success.
- Added current revision-specific verification, distinguished historical WSL2
  records, and documented pending rubric/video evidence.
- Updated reservation course/status and knowledge-graph runner coverage.

The recorded macOS OS-30 result was **116/116, exit code 0** in 53.395s, from
`python3 -m unittest discover -s linux-lab/tests -v`, on `d5ba261d` plus the
then-uncommitted OS-30 fixes (including the UFW failure/interruption policy).
This identifies the tested tree at execution time, not the current branch tip.
The **115-test** result is the previous run after the quoted-Ubuntu-ID fix,
not the latest result. `git diff --check` passed (exit 0). Bash syntax,
ShellCheck and Python AST checks passed in their recorded runs.

The complete repository check is not green on this macOS ARM64 / Python 3.14
host: Android/console and Cleanup Lab tests fail outside the OS-30 files.
`lat check` also reports an existing paragraph-length error in
`lat.md/cleanup-lab.md:237` (339 characters; maximum 250), so `lat check`
failed with exit code 1. The last recorded full repository runner result remains
**5 stages passed, 2 failed, 3 skipped; exit code 1**; it was not rerun for this
documentation update. Those paths have no diff against the fetched PR
target. See `VERIFY.md` for counts and commands; no general CI pass is claimed.

## Scope

`linux-lab/scripts/harden_check.py` provides a local Ubuntu Server baseline audit,
read-only repair planning, approval-gated repairs and explicit rollback. It uses
Python's standard library and delegates audit collection to `hardening.sh`.
Missing/empty collector code and an execution producing no findings are refused.

Audit is the default. It does not modify configuration, refresh package lists,
install updates, restart services or change firewall rules. Commands use a fixed
system PATH; `.env` and host-forwarded SSH ports are not used. Output is available
as text or versioned JSON with PASS, FAIL, WARN and SKIP findings. Exit 0/1 is
reported only for a complete collector run whose final summary matches its
findings and exit code; truncated or inconsistent output exits 2. With
`--format json`, platform and collector errors are also valid JSON.

## Audit coverage

- SSH service/socket state, attributed TCP listeners, effective `sshd -T/-C`
  settings, syntax validation and standard config ownership/permissions.
- Non-root UID 0 accounts, interactive accounts, password state, sudoers syntax
  and privileged noninteractive sudo policy listings. `/bin/sync` is not a shell.
- Cached pending/security-labelled updates, cache age, unattended-upgrades
  package/policy/timer state and reboot marker.
- UFW status, rules and defaults against an active, deny-incoming/allow-outgoing
  baseline. Missing privileges or inconclusive evidence remain WARN.

## Repairs and rollback

`plan` previews explicitly selected repairs without writes. `apply` requires root,
input/output TTYs and the exact phrase `APPLY OS-30`. Supported repairs are:

- Optional stricter root-owned SSH configuration modes to 0600, with `sshd -t`
  before/after. An existing 0644 file can already pass the audit; 0644 -> 0600
  is not automatically remediation of an existing FAIL.
- An explicit non-root user's existing authorized_keys mode to 0600.
- Enablement of an installed unattended-upgrade timer without starting it.
- One management-IP allow rule to an attributed actual SSH port. Existing rules
  are classified by UFW's identity fields in both plan and apply: an equivalent
  allow rule is a SKIP; a deny/reject/limit rule for the same connection is
  refused before any change (UFW would replace it); rules differing in
  direction, interface or source port stay unchanged. Apply repeats the check
  immediately before `ufw allow`.

Apply retains private snapshots and schema-2 manifests under
`/var/backups/os-30/repair-<run-id>`, including verified post-state. Shared locking,
no-follow file access, target allowlists and drift checks protect repair/recovery.
SIGINT/SIGTERM/SIGHUP during apply stop at a checkpoint, reverse proven
permission/timer changes and record status `interrupted` with reverted/unreverted items
(exit 130/143/129). Failed or interrupted apply never deletes a UFW rule, even
when verified. An attempted addition retains its backup and manifest and reports
manual rule-state inspection with the backup path. Only an explicitly confirmed
rollback of a successfully applied run may remove its verified rule. Manual recovery for unfinished runs is documented in
`linux-lab/knowledge/hardening.md`.

```text
sudo python3 linux-lab/scripts/harden_check.py rollback <run-id>
```

Rollback previews changes and requires exact `ROLLBACK OS-30 <run-id>` consent.
It restores only recorded permission modes and timer enablement changed by that
run. Contents and ownership are not overwritten. Only a uniquely tagged UFW rule
proven to be that run's single addition may be removed. Ambiguous firewall state
produces a partial result and retained backup path, without guessed deletion or
reset. Progress is journaled for safe retries; a completed rollback is a no-op.
Legacy, incomplete, corrupt or unsafe backups and unexpected target drift are
refused.

No repair disables SSH root/password authentication, locks/deletes accounts,
installs packages, activates UFW or replaces its defaults. Future timer schedules
may install updates under existing policy. A successful selected repair does not
imply a clean baseline audit. Custom Include/parent permissions, service-account
and external sudo semantics, full package-origin classification and end-to-end
network reachability remain outside complete automated coverage.

## Files

- `linux-lab/scripts/harden_check.py`: CLI, reports, repair and rollback logic.
- `linux-lab/scripts/hardening.sh`: read-only Bash audit collectors.
- `linux-lab/tests/test_hardening.py`: mocked Bash collector tests.
- `linux-lab/tests/test_harden_check.py`: repair/CLI/guard/PTY tests.
- `linux-lab/tests/test_rollback.py`: rollback, drift, recovery and attack tests.
- `scripts/run-tests.sh`: integration with the repository test runner.
- `linux-lab/README.md`, `linux-lab/knowledge/hardening.md`: usage and recovery.
- `lat.md/linux-lab.md`: architecture and implementation links.
- `VERIFY.md`: executed checks and live evidence boundaries.

## Evidence boundary

The companion Bash collector is part of the deliverable and remains audit-only.
The repository runner preserves its existing stages with an added OS-30 unittest
stage; no unrelated runner implementation was replaced.

### Historical UTM verification — 2026-11-13, `bdcc521`

Operator-reported Ubuntu 24.04 ARM64 UTM results for `bdcc521`:

- Text audit: **3 FAIL, 18 WARN, exit code 1**.
- JSON audit: valid JSON, schema version `1`, `exit_code: 1`, with
  **15 PASS, 18 WARN, 3 FAIL**.
- Read-only permission plan: `/etc/ssh/sshd_config` **0644 → 0600**;
  no change was applied. Mode 0644 can already pass the audit; the plan is an
  optional stricter mode, not proof of an existing permission FAIL.

These are historical operator-reported checks, supplied for the record and not
re-executed during that preparation. Raw identifying server output is excluded.

Focused test commands and results are recorded in `VERIFY.md`. Historical
local runs are labeled separately and are not presented as new executions.

## Historical WSL2 focused verification (2026-11-13)

Recorded run: uncommitted working tree on base commit `bdcc521`, Ubuntu 24.04.3
LTS on WSL2 (x86_64), Python 3.12.3: `python3 -m unittest discover -s
linux-lab/tests -v` passed **114 tests**, exit 0. The patch hash, environment
details and a reverse check (the new regression tests fail on unpatched
`bdcc521`) are in `VERIFY.md`. This is mock/fixture evidence on x86_64, not a
live UTM ARM64 apply/rollback.

### Historical pre-commit verification (before `bdcc521`)

The pre-delivery run of
`python3 -m unittest discover -s linux-lab/tests -v` passed **97 tests in 52.513s**,
exit 0, after restoring the test-runner cd guard. Python/Bash syntax, existing ShellCheck and both
working-tree/index whitespace checks passed. The existing collector source was
completed and regressions now prevent missing, empty or non-reporting collectors
from being presented as a successful audit.

No package installation, full-runner execution or live host/VM security change
was performed. The graph checker was unavailable; the subsequent npx attempt
failed to retrieve lat.md with `ENOTFOUND` for `registry.npmjs.org`, so graph
validation could not run. No global installation or `lat init` was performed.
After the checks passed, the reviewed OS-30 files and README image
were staged; no commit or push was made. Subsequent documentation corrections
require their own staging review. No live audit was run during integration;
the UTM text/JSON audits and read-only plan were operator-reported on
`bdcc521` on 2026-11-13. `VERIFY.md` distinguishes those checks from local mock evidence.
