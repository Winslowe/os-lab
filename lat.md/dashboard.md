# Dashboard

The browser console: the host overview, every lab, and the Android Lab
workbench, built from the qLar app shell (qLar PR #174).

## Architecture

A static Astro app in [[dashboard]] served by the Python console; there is no
Node server at runtime.

[[dashboard/src/shell/app-shell.tsx]] carries the sidebar (labs with their
availability pills), Spotlight and theme ported from qLar. Pages are React
islands: [[dashboard/src/views/host-page.tsx]],
[[dashboard/src/views/lab-page.tsx]], [[dashboard/src/views/jobs-page.tsx]],
[[dashboard/src/views/contribute-page.tsx]] and
the Android workbench in [[dashboard/src/views/android/pages.tsx]].
[[dashboard/src/lib/api.ts]] is the typed client; it mirrors qLar's
`shared/os-lab.ts` contract.

## iOS Simulator panel

When the iOS Lab is ready through the native-macos provider,
[[dashboard/src/views/ios-simulator.tsx]] replaces the plain start/stop
buttons with a device frame: a device picker, previewed attach/detach, a
toggleable bezel and a live screen.

The screen comes from the read-only `/api/labs/ios/simulator` and
`/api/labs/ios/screenshot` endpoints. The panel still routes every state
change through the previewed plan flow; the console validates the device
against `xcrun simctl` (see [[ios-lab]]).

## UX readiness

[[ux-readiness]] records the dashboard's action, endpoint, and navigation
rules. The detailed implementation checklist is [[docs/UX_READINESS.md]].
The feedback route is in [[dashboard/src/views/feedback-page.tsx]].

## Host engine

[[console/oslab.py]] ports the qLar desktop OS Lab runtime to the Python
standard library.

It detects the host (OS, arch, CPU, memory, disk, KVM, WSL distributions and
tools), decides each lab's state and provider (linux-containers, wsl2,
native-macos or macos-containers), builds typed, validated plans for lab
actions, runs them as background jobs with secret redaction, timeouts and
cancellation, and reports container state. Privileged setup runs through
pkexec when a graphical agent exists; otherwise the plan returns a `sudo`
command to run in a terminal.

The Source Lab evidence/report readers in
[[console/source_artifacts.py]] reuse the console's localhost Host guard without
starting analyses or changing state. Additional [[console/source_api.py]] handlers
use the shared preview and jobs service for explicit actions. Source readiness
runs natively through Python, and public Source routes show information without
polling a local engine. See [[source-lab#Console operations]].

## Serving and builds

[[android-lab/lab/web_ui.py]] serves the newest of `dashboard/build` (local)
and `dashboard/dist` (committed), else the classic console.

The installers build `dashboard/build` when Node.js 22+ is present, so hosts
without Node use the committed `dashboard/dist`. Every POST must carry
`X-OSLab: 1` and every request a localhost `Host`, so other sites cannot drive
the lab. Lab starts require the token returned by the plan preview. See
[[tooling#Local test runner]] for the build freshness check.

## Source navigation

Cleanup Lab navigation links to scan, results, leftovers and history in
[[dashboard/src/views/cleanup/pages.tsx]]. The public route explains that the
engine is local, while the local app uses typed cleanup jobs and a confirm step.

[[dashboard/src/views/source/pages.tsx]] provides localized Source Lab routes and
uses the existing shell for mobile navigation and themes. The sidebar and
Spotlight include Source destinations; record search reads private file-backed
results only while the local palette is open.

Public Source pages are informational, make no engine requests, and preserve
locale/base/query links. Missing private artifacts/providers say so explicitly.

[[dashboard/src/views/source/overview.tsx]] renders file-backed Overview matrices,
inspector notes, filters, CSV/JSON links and operator source catalogs.
[[console/source_overview.py]] adapts raw and flattened crawler manifests and
per-package dependency sections without importing private datasets.

[[dashboard/src/views/source/crawler.tsx]] validates selected source lists or
repository slugs, workers/depth and crawler options. Live Source readiness and
Git gate actions; previews invalidate on edits. Runs use the existing jobs API
for output, cancellation and conflicts. No progress percentage is invented.

[[dashboard/src/views/source/evidence.tsx]] exposes findings, coverage, H1-H5
scorecards, sessions/events and report links. Detection uses the shared
[[dashboard/src/views/source/action.tsx]] preview/job component. Evidence states,
partial coverage and browsing-without-verification remain explicit.

[[dashboard/src/views/source/runtime.tsx]] manages key status and previewed
generation/rotation, configured canary URL and explicit session verification.
Environment-owned keys are read-only; rotation needs acknowledgement and command
confirmation. Evidence collection modes distinguish static, canary and selected
sessions; optional browser tooling never blocks static analysis.

[[dashboard/src/views/source/deep.tsx]] browses bundles, source and indexed AST
artifacts through repo/file deep links. Its structural map dialog filters files
by role/language and shows stats, targets, coverage, symbols and imports.

Map navigation is distinct from evidence. Available private targets have a
bound crawler action; missing maps/workspaces are explicit unavailable states.

## Brain providers

[[source-lab/BRAIN.md]] records embedding/provider decisions for every retained
Brain subview. The prototype runs in the existing React island without new
packages or a live Laravel service.

[[dashboard/src/views/source/brain-model.ts]] validates bounded graph windows and
[[dashboard/src/views/source/brain-data.ts]] reads only validated private JSON
provider paths. Duplicate nodes, oversized graphs and unsafe paths fail clearly.

[[dashboard/src/views/source/brain.tsx]] provides paged SVG/keyboard graph
navigation, filters/legend, usages, source/history/diff, flow/sequence, static
AI-rule review, recorded-metric rankings and full snapshot JSON export.

Absent providers, including live application stress testing, stay explicitly
unavailable. Snapshot relationships never claim to be runtime traces.

## Source workflow documentation

[[dashboard/src/views/source/docs.tsx]] renders trusted first-party guides from
[[dashboard/src/lib/source-docs.ts]] in local and public localized routes.

The English technical prose is labeled; navigation and internal guide/legal
links preserve locale/base paths. No private artifact or OpenAPI reference is
rendered. [[source-lab/RUNBOOK.md]] records operation/recovery and native bonus checks.

[[dashboard/src/views/source-bonus-tasks.tsx]] adds six open, reservable Source
verification/patch tasks to Contribute. They preserve explicit native/live limits.

## Task prompt builder

[[dashboard/src/views/how-to-use-page.tsx]] adds How to use under Workspace in
both navigation modes, with localized `/how-to-use/` routes.

[[dashboard/src/lib/how-to-use.ts]] combines the user task with the shipped
[[console/capabilities.json]] catalog, platform limits, workflow guidance and
repository/legal references. It never reads a live host report or calls an LLM.
Submit generates and copies the prompt; clipboard failures retain a selectable
preview with retry. Tasks remain in browser memory, without URL/storage persistence.
[[scripts/deploy-page.sh]] retains these routes in every public locale.

The prompt embeds the complete [[docs/HOW_TO_USE_CHEATSHEET.md]] and
[[docs/HOW_TO_USE_COMMANDS.md]], including requirements, operations and recovery
for every lab. [[scripts/build-how-to-use-reference.py]] extracts exact parser,
Make target, PowerShell parameter and configuration-name references from an
explicit source allowlist without executing code or reading private state.
Regenerate it after those sources change; `--check` detects stale output.
