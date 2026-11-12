# Repository tooling

Cross-cutting process, tests and conventions for the monorepo: CI, the android
test suite, contribution flow and the project's security/licensing stance.

## Local test runner

The local runner complements enabled browser/content and Linux/macOS package
workflows. Windows review builds do not imply permission to publish without
Authenticode; its workflow requires SignPath or explicit unsigned-release approval.

[[scripts/run-tests.sh]] is the CI replacement. It prepares a Python
environment (a `.venv-test` unless `--no-venv`), runs the pytest suite in
[[android-lab/lab/tests]], runs a sample-analysis smoke test, checks every
shell script with `bash -n`, runs `lat check` when `lat` is installed, and,
when `dashboard/node_modules` exists, typechecks the [[dashboard]] and fails if
the committed `dashboard/dist` differs from a fresh build.
`--quick` runs only the unit tests. The dormant workflow file
[[.github/workflows/mobile-sec-scan.yml]] is kept for reference but is disabled.

## Tests

Android and Source Lab have independent automated test suites.

It lives in [[android-lab/lab/tests]] (analyzer, reporter, MobSF client, secret
scanner, patcher, flow parser, agentic engine, web UI, and the host engine in
[[console/oslab.py]]). Shell scripts across the
VM labs are kept `bash -n` clean and use `set -euo pipefail`.
The [[source-lab]] engine tests run in their own process from
[[source-lab/engine]] so their imports cannot collide with Android tests.

## Firewall rule renderer

[[firewall-lab/vm/scripts/render-rules.py]] turns a company's abstract rules into UFW
commands, an nftables ruleset or a vendor-neutral table, so the same ordered policy
can be loaded in the disposable firewall guest.

Port handling follows the declared rule exactly. A comma list becomes an nft
anonymous set (`dport { 22, 443 }`) and stays a UFW multiport list. `proto: any`
with a port means TCP or UDP to those ports (`meta l4proto { tcp, udp } th dport`
in nft, one tcp and one udp command in UFW), never all traffic. A port on `icmp`
is ignored by both backends. Items that are not ports or ascending ranges in
1–65535 (`esp`, `80,,443`, `500:400`) are skipped with a comment and a stderr
warning. Notes and names are flattened to one line before they go into comments.
[[.github/workflows/firewall-lab.yml]] renders every branch of every company and
checks the output with `nft -c` and `bash -n`, and rejects duplicate branch ids.

## Community and contribution

Contribution flow, coding conventions and the authorization stance.

They are in [[CONTRIBUTING.md]], step by step from setup to pull request, and
the [[dashboard]] renders the same file at `/contribute/`. Contributions must not
add vendor binaries or proprietary media (see [[legal#Google platform-tools]]).
The Source Lab migration is tracked in [[source-lab/README.md]], with its plan,
task queue and pinned source inventory. [[source-lab]] records the implemented
engine, console and file-backed dashboard workflows. Remaining native/live
verification and patches are open Source bonus tasks in [[CONTRIBUTING.md]].

Issue and PR templates are in
[[.github/ISSUE_TEMPLATE]] and [[.github/PULL_REQUEST_TEMPLATE.md]]; behavior
expectations in [[CODE_OF_CONDUCT.md]].

## Security and licensing

Private vulnerability reporting and the authorization-only scope.

These are defined in [[SECURITY.md]]; the project is Apache-2.0 ([[LICENSE]]).
The VM base images (`dockur/windows`, `qemux/qemu`, `dockurr/macos`) are MIT and
do not distribute OS media; users are responsible for valid licences.

[[dashboard/scripts/source-brain-model.test.mjs]] validates provider paths, graph
limits/windows and bounded revision diff without a browser.
[[source-lab/RUNBOOK.md]] records the portable release/rollback workflow.

## Two-stage dropper detection harness

[[scripts/analysis/dropper_detect.py]] and [[scripts/analysis/dropper_lab/README.md]]
provide an offline static and loopback-rehearsal detector for two-stage "clean dropper"
loaders (`PENT-15`), correlating remote stage fetch, deferred triggers, payload decoding
and dynamic execution sinks while keeping benign utilities false-positive free.

