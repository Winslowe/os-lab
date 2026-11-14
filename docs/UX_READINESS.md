# UX readiness guidelines

These guidelines apply to the local dashboard's host and lab pages, the Android workbench, and the public Pages site. The architecture map is in [`lat.md/lat.md`](../lat.md/lat.md); the dashboard-specific graph node is [`lat.md/ux-readiness.md`](../lat.md/ux-readiness.md).

The proposed extension and its tracked acceptance work are in the [UX guideline patch plan](UX_GUIDELINE_PATCH_PLAN.md) and [checklist](UX_GUIDELINE_PATCH_TODO.md).

## Build behavior before visual design

- For a new feature, define its types, state/store, API contract, and error states first. Add plain, accessible pages and controls that exercise the real capability. Verify the scan, preview, confirmation, result, retry, and failure paths that apply before starting a visual design pass.
- Keep safety and UX truth in the functional pass: show readiness, unavailable reasons, operation errors, destructive consequences, and keyboard-accessible controls from the start. A plain page must still be usable.
- Once the logic and local/public routes work, apply the visual design in a focused pass. Preserve existing working design; avoid repeated styling changes while debugging API or state behavior.
- Track each Cleanup Lab task in its own PR, even when tasks are worked sequentially as a batch. Record the functional and visual verification still due in that task's PR rather than treating a backend-only draft as complete.

## Show actions only when they make sense

- Derive setup actions from the current host report. Show **Install dependencies** only when a required prerequisite is missing and the lab exposes a `setup` action. The backend decides the `ready`, `needs-setup`, and `unavailable` states; do not infer readiness from the mere presence of an action.
- Keep optional tooling separate. For example, a missing Appium installation can offer **Install Appium** without making an otherwise ready simulator appear blocked.
- Preview lab actions before running them. A preview must state the command, effects, privileges, and downloads; execution starts only after confirmation.
- Disable an action while its request is being submitted or a conflicting job is running. Put a failed request's error next to the action that failed.
- Treat cancellation, log clearing, polling, and other follow-up requests the same way: show pending state, report failure beside the control or job, allow a safe retry, and trust the server for the final state. A failed cancellation must leave the running job and its output visible.
- If no setup action exists, direct users to the relevant manual requirement or platform guidance instead of promising an unavailable install flow.

## Keep the default view compact and honest

- Put configuration files, profiles, and endpoint addresses in a collapsed **Advanced settings** area on lab runtime pages. Keep required dependency status visible while anything is missing, and keep primary actions visible; once every tracked requirement is found, the Dependencies card may hide so the actions take the full row.
- Describe an address as *configured* until the service is running. A known URL is not proof that it responds. Keep secondary Android endpoint lists collapsed and explain when they are usable.
- Preserve a way to inspect details and copy addresses. Mask secrets before they reach the UI.
- Use explicit loading, empty, success, and error states. Avoid cards that imply an operation succeeded before the API confirms it.
- A Copy control reports success only after the clipboard write resolves. If it fails, keep the text available for manual selection. External release lookups must leave loading state after failure and retain an honest release-page fallback.
- Label Source Lab evidence as live, imported, synthetic, or partial, and show its collection time where relevant. Missing tools, empty coverage, and an unavailable provider do not prove a clean live target. Keep private artifacts and secrets out of public Pages.
- Keep standing guidance short when the nearby status and action already explain it. Preserve setup, security, download, privilege, cancellation, and evidence-limit warnings at the decision point.

## Keep controls usable across devices

- Shared buttons, icon actions, dialog close controls, and dense text actions need usable coarse-pointer targets (about 44×44 CSS pixels where space allows), without enlarging desktop layouts or making the page pan horizontally.
- Modal overlays keep keyboard focus inside until dismissed. Escape, backdrop and close actions return focus to the trigger. A tablist supports arrow-key movement, a selected tab and its labelled panel; otherwise use ordinary button semantics.
- Check narrow widths, 200% text zoom, visible keyboard focus, both themes, and Arabic/Persian right-to-left layouts. Let wide data scroll within its own region, not the whole page.

## Match the environment

- The local app can show engine connection and job status. Public Pages has no local engine, so it must not display a perpetual connection indicator or local-only actions as if they work there.
- Build internal links with the locale and the Pages base path. Test language switching both from English and from a non-English route under `/os-lab/`.
- Keep feedback reachable from local and public navigation. Bug and feature links use repository issue templates; discussions handle general feedback; vulnerability reports go to a private security channel.
- Add visible UI copy to every active locale catalog (currently eight, as defined by `FIREWALL_LOCALES` in `dashboard/src/firewall/locale.ts`) and run the translation check.

## Review and verification

Check ready, missing-required, missing-optional, unavailable, loading, and failed-request states on each relevant page. Smoke-test every page type for hydration errors. For dashboard changes, run `npm run check`, `npm run test:i18n`, `npm run build`, and `npm run test:e2e` in `dashboard/`. When Pages routing changes, build with `PUBLIC_SITE_MODE=pages` and `SITE_BASE=/os-lab`, then test links and locale switching in a browser. Run `lat check` after changing `lat.md/`.
