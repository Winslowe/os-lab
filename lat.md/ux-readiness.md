# UX readiness

The interface should show a next step that the current host can actually take. The detailed checklist is [[docs/UX_READINESS.md]].

For new features, implement types, state/store and API contracts, then plain
usable pages and components. Verify real success and failure paths before a
focused visual design pass. Preserve working UX and track each Cleanup Lab task
in a separate PR; an engine-only draft still has an open page gate.

## Lab state and actions

[[console/oslab.py]] produces each lab's requirements, state, provider, and available actions. [[dashboard/src/views/host-page.tsx]] and [[dashboard/src/views/lab-page.tsx]] offer setup only when a required prerequisite is missing.

Optional Appium tooling has its own action. Lab actions go through a preview and then a background job.

The Jobs page reports cancellation failure beside the selected job and keeps its logs visible; the Android execution console reports log-clearing failure without clearing the displayed output. Both disable repeated requests while submitting. A successful follow-up refreshes server state.

## Detail and endpoint status

[[dashboard/src/views/lab-page.tsx]] keeps the Dependencies card visible while
anything is missing and hides it once every tracked requirement is found, so
actions take the whole row. Endpoints and configuration stay in a collapsed
Advanced settings panel.

[[dashboard/src/views/android/pages.tsx]] keeps its secondary emulator endpoint
list compact.

An address from configuration describes where a service would answer; it does not establish that the service is running.

[[dashboard/src/components/ui.tsx#CopyButton]], the Contribute task list, and public-home setup commands report clipboard success only after the write resolves; failures offer manual selection. Public-home release lookup leaves the checking state on failure and points to the release page.

[[dashboard/src/views/contribute-modal.tsx]] and [[dashboard/src/views/gap-modal.tsx]] use native modal dialogs for focus containment and Escape handling. The Cleanup Lab confirmation dialog in [[dashboard/src/views/cleanup/pages.tsx]] follows the same recipe, and the cleanup cards keep decisions (name, risk, size, selection) on the card while hints, impacts, paths, sources and privilege notes live in the hover/focus popover from [[dashboard/src/views/cleanup/info-popover.tsx]]. [[dashboard/src/views/health-page.tsx#PlatformTabs]] and [[dashboard/src/views/firewall-company-page.tsx]] connect selected tabs to panels and support arrow keys. Shared `.iux-btn` controls and marked exceptions gain larger targets on coarse pointers.

## Public and local navigation

[[dashboard/src/shell/top-bar.tsx]] shows engine status only in the local app. [[dashboard/src/i18n/paths.ts]] handles locale and Pages base paths. [[dashboard/src/views/feedback-page.tsx]] provides issue, feature, discussion, and private security routes from both navigation modes.

Legal Markdown cross-links in [[dashboard/src/lib/legal.ts#rewriteLinks]] and
legal tabs/cards in [[dashboard/src/views/legal-page.tsx]] preserve the current
locale and Pages base path. Article links are localized at build time because
legal prose is excluded from client translation.

## Verification

[[dashboard/e2e/cleanup.spec.ts]] checks the typed scan → plan → confirm → clean
flow and the public Turkish `/os-lab/tr/cleanup/` route without engine calls.

[[dashboard/e2e/health-and-content.spec.ts]] covers dependency actions, advanced details, run failures, and hydration across page types. Dashboard type, translation, and static build checks complement browser tests. Public Pages links and locale switching are checked under `/os-lab/`.

[[dashboard/scripts/source-pages-smoke.mjs]] checks every Source route and guide
across all eight locales below `/os-lab/`, including query-preserving language
switches. Public pages must issue no engine calls or operation controls.

[[scripts/deploy-page.sh]] must retain public Source guides and community/legal
links in every locale while filtering console-only routes. Test its final
post-processed artifact, not only the raw Astro Pages output.

[[dashboard/scripts/how-to-use-pages-smoke.mjs]] checks the Workspace task
prompt builder across all eight public locales, including clipboard output,
language switching, mobile layout and absence of engine calls. Run both public
smoke scripts after applying the deployment filters.
