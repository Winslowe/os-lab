/**
 * /labs/<lab>/ — one lab on this computer: dependencies, actions, previewed plans, live jobs,
 * container monitor and configuration. Ported from qLar's settings/os-lab-jobs.tsx and
 * os-lab/lab-page.tsx (PR #174): every action is previewed (exact command, effects, setup
 * prerequisites, privileges) before it runs, and runs as a background job with retained output.
 */
import { useEffect, useMemo, useState, type ReactNode } from "react";
import {
  ArrowClockwiseIcon,
  CheckCircleIcon,
  CircleNotchIcon,
  GearSixIcon,
  InfoIcon,
  PlayIcon,
  PulseIcon,
  ShieldWarningIcon,
  StopIcon,
  WarningCircleIcon,
  WrenchIcon,
  XCircleIcon
} from "@phosphor-icons/react";
import { AppShell, LAB_ICON } from "../shell/app-shell";
import { TopBar } from "../shell/top-bar";
import { ShellSnippet } from "../apk-lab/components";
import { Badge, Empty, EndpointList, Field, PageHead, Section, Skeleton, Status } from "../components/ui";
import { SimulatorPanel } from "./ios-simulator";
import { stateBadge } from "./host-page";
import {
  ago,
  api,
  hostStore,
  jobsStore,
  message,
  usePoll,
  type LabId,
  type LabJob,
  type LabPlan,
  type LabRequest,
  type LabStatus
} from "../lib/api";

/** Reference commands for hosts where a lab is unavailable (from qLar's os-lab/lab-page.tsx). */
const REFERENCE: Record<LabId, { check: string; setup: string; where: string }> = {
  android: { check: "./labctl android doctor", setup: "./labctl android start --wait", where: "android-lab/lab" },
  windows: { check: "./labctl win status", setup: "./labctl win profile use development\n./labctl win start --wait", where: "win-lab" },
  linux: { check: "./labctl linux status", setup: "./labctl linux profile use development\n./labctl linux start --wait", where: "linux-lab" },
  ios: { check: "./labctl ios status", setup: "./labctl ios profile use development\n./labctl ios start --wait", where: "ios-lab" },
  source: { check: "./labctl source doctor", setup: "./labctl source setup", where: "source-lab" },
  macos: { check: "make -C ios-lab mac-doctor", setup: "make -C ios-lab mac-setup mac-sim mac-appium", where: "ios-lab/mac" }
};

const ACTION_GROUPS: { title: string; ids: string[] }[] = [
  { title: "Automation", ids: ["appium-install", "idb-install", "xcuitest-smoke"] },
  { title: "Inspect", ids: ["status", "doctor", "urls", "logs", "monitor"] },
  { title: "Maintenance", ids: ["backup", "service-install", "service-uninstall"] }
];

/** Start/stop clusters render as one segmented icon control per tool, titled by what it drives. */
const SEGMENT_GROUPS: { title: string; ids: string[] }[] = [
  { title: "Stack", ids: ["start", "stop", "restart"] },
  { title: "Appium", ids: ["appium-start", "appium-stop"] },
  { title: "idb", ids: ["idb-start", "idb-stop"] }
];

/** One icon per segment; start segments keep the primary (orange) affordance. */
const SEGMENT_ICON: Record<string, ReactNode> = {
  start: <PlayIcon size={14} weight="fill" />,
  stop: <StopIcon size={14} />,
  restart: <ArrowClockwiseIcon size={14} />,
  "appium-start": <PlayIcon size={14} weight="fill" />,
  "appium-stop": <StopIcon size={14} />,
  "idb-start": <PlayIcon size={14} weight="fill" />,
  "idb-stop": <StopIcon size={14} />
};

/** Optional dependencies that have a one-click install action, keyed by requirement id. */
const OPTIONAL_INSTALLS: Record<string, { action: string; label: string }> = {
  appium: { action: "appium-install", label: "Install Appium" },
  idb: { action: "idb-install", label: "Install idb" }
};

/** Scripts print `##PROGRESS n/total label` per step; the last one drives the bar and the lines stay out of the output. */
const PROGRESS = /^##PROGRESS (\d+)\/(\d+) (.*)$/;
export function readProgress(lines: string[]): { step: number; total: number; label: string } | null {
  for (let i = lines.length - 1; i >= 0; i--) {
    const m = PROGRESS.exec(lines[i].trim());
    if (m && Number(m[2]) > 0) return { step: Math.min(Number(m[1]), Number(m[2])), total: Number(m[2]), label: m[3] };
  }
  return null;
}

function Requirements({ lab, onInstall }: { lab: LabStatus; onInstall?: (action: string) => void }) {
  if (!lab.requirements.length) return <Empty>No host prerequisites are tracked for this lab.</Empty>;
  return (
    <ul className="divide-y divide-(--iux-border)">
      {lab.requirements.map((r) => (
        <li key={r.id} className="flex flex-wrap items-center gap-2.5 py-2.5 text-sm">
          {r.found ? (
            <CheckCircleIcon size={16} weight="fill" className="shrink-0 text-(--iux-success)" />
          ) : r.required ? (
            <XCircleIcon size={16} weight="fill" className="shrink-0 text-(--iux-danger)" />
          ) : (
            <WarningCircleIcon size={16} className="shrink-0 text-(--iux-muted-foreground)" />
          )}
          <span className="min-w-0 flex-1 basis-40">
            {r.label}
            {!r.found && r.hint ? <span className="block text-xs text-(--iux-muted-foreground)">{r.hint}</span> : null}
          </span>
          {!r.found && OPTIONAL_INSTALLS[r.id] && onInstall && lab.actions.some((a) => a.id === OPTIONAL_INSTALLS[r.id]!.action) ? (
            <button type="button" className="iux-btn" onClick={() => onInstall(OPTIONAL_INSTALLS[r.id]!.action)}>
              {OPTIONAL_INSTALLS[r.id]!.label}
            </button>
          ) : null}
          <Badge tone={r.found ? "success" : r.required ? "danger" : undefined}>
            {r.found ? "found" : r.required ? "missing" : "optional"}
          </Badge>
        </li>
      ))}
    </ul>
  );
}

function PlanPanel({
  title,
  plan,
  busy,
  error,
  onRun,
  onCancel
}: {
  title: string;
  plan: LabPlan | null;
  busy: boolean;
  error: string | null;
  onRun: () => void;
  onCancel: () => void;
}) {
  return (
    <section id="plan" className="iux-card gap-4 border-[#f36c21]/50 py-5">
      <div className="flex flex-wrap items-start gap-3 px-5">
        <div className="min-w-0 flex-1">
          <h2 className="flex items-center gap-2 text-sm font-semibold">
            <ShieldWarningIcon size={16} className="text-[#f36c21]" />
            {plan ? `${title}?` : "Preparing preview…"}
          </h2>
          <p className="mt-1.5 text-sm text-(--iux-muted-foreground)">
            Nothing runs until you confirm. Jobs keep running when this page is closed; output is kept on this computer.
          </p>
        </div>
        {plan ? (
          <div className="flex gap-2">
            {plan.privileged ? <Badge tone="warning">Administrator</Badge> : null}
            <Badge>{plan.provider}</Badge>
          </div>
        ) : null}
      </div>
      <div className="flex flex-col gap-4 px-5">
        {error ? <Status value={{ ok: false, text: error }} /> : null}
        {plan ? (
          <>
            <pre className="overflow-x-auto rounded-lg border border-(--iux-border) bg-(--iux-muted) px-4 py-3 font-mono text-xs">{plan.display || "(run manually)"}</pre>
            <ul className="list-disc space-y-1 pl-5 text-sm">
              {plan.effects.map((e) => (
                <li key={e}>{e}</li>
              ))}
              <li>Timeout: {Math.round(plan.timeoutSec / 60) || 1} min</li>
            </ul>
            {plan.setup ? (
              <div className="rounded-xl border border-dashed border-(--iux-border) p-4 text-sm">
                <h3 className="mb-2 font-semibold">Dependencies this installs or checks</h3>
                <ul className="list-disc space-y-1 pl-5">
                  {plan.setup.dependencies.map((d) => (
                    <li key={d}>{d}</li>
                  ))}
                </ul>
                <div className="mt-3 space-y-1.5 text-xs text-(--iux-muted-foreground)">
                  {plan.setup.downloads.map((d) => (
                    <p key={d}>{d}</p>
                  ))}
                  <p>
                    <strong className="text-(--iux-foreground)">Disk:</strong> {plan.setup.guestDisk ? `${plan.setup.guestDisk} guest capacity. ` : ""}
                    {plan.setup.diskNote}
                  </p>
                  <p>
                    <strong className="text-(--iux-foreground)">Privileges:</strong> {plan.setup.privileges}
                  </p>
                  {!plan.setup.verifiedDownloads ? <p>Download versions and checksums are not verified by this preview.</p> : null}
                </div>
              </div>
            ) : null}
            {!plan.runnable && plan.manualCommand ? (
              <div className="space-y-2">
                <p className="text-sm">No graphical authorization prompt is available to this console. Run this in a terminal, then press Re-detect:</p>
                <ShellSnippet tabs={[{ id: "manual", label: "terminal", command: plan.manualCommand }]} showTabs={false} prefix="$" />
              </div>
            ) : null}
          </>
        ) : !error ? (
          <Skeleton rows={2} />
        ) : null}
        <div className="flex flex-wrap gap-2">
          {plan?.runnable ? (
            <button type="button" className="iux-btn bg-[#f36c21] text-white hover:bg-[#fa7b32]" disabled={busy} onClick={onRun}>
              <PlayIcon size={14} weight="fill" /> {busy ? "Starting…" : "Run"}
            </button>
          ) : null}
          <button type="button" className="iux-btn" data-variant="outline" onClick={onCancel}>
            {plan?.runnable ? "Cancel" : "Close"}
          </button>
        </div>
      </div>
    </section>
  );
}

function JobPanel({ jobs, selected, onSelect }: { jobs: LabJob[]; selected: string | null; onSelect: (id: string) => void }) {
  const id = selected ?? jobs[0]?.id ?? null;
  const current = jobs.find((j) => j.id === id);
  const detail = usePoll(() => (id ? api.job(id) : Promise.resolve(null)), current?.state === "running" ? 1500 : 0, [id, current?.state]);
  const [cancelling, setCancelling] = useState(false);
  const [cancelError, setCancelError] = useState<string | null>(null);
  if (!jobs.length) return <Empty>No jobs for this lab yet. Preview an action above to start one.</Empty>;
  const rawLogs = detail.data?.id === id ? detail.data.logs ?? [] : [];
  const progress = readProgress(rawLogs);
  const logs = rawLogs.filter((line) => !PROGRESS.test(line.trim()));
  return (
    <div className="iux-card gap-4 p-5" aria-busy={current?.state === "running"}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 className="text-sm font-semibold">{current?.label ?? "Job"}</h3>
          <p className="mt-1 text-xs text-(--iux-muted-foreground)">
            Started {ago(current?.startedAt)}{current?.exitCode != null ? ` · exit ${current.exitCode}` : ""}
          </p>
        </div>
        <Badge tone={current?.state === "succeeded" ? "success" : current?.state === "running" ? "warning" : "danger"}>
          {current?.state === "running" ? <CircleNotchIcon size={13} className="mr-1 inline animate-spin" /> : null}
          {current?.state ?? "unknown"}
        </Badge>
      </div>
      {current?.state === "running" ? (
        <div role="status" className="space-y-1.5 text-xs text-(--iux-muted-foreground)">
          <p>
            {progress
              ? `Step ${progress.step} of ${progress.total}: ${progress.label}`
              : current.action === "setup" ? "Installing and checking dependencies…" : "Running action…"}{" "}
            Output appears below as each step completes.
          </p>
          <div
            className="h-1.5 overflow-hidden rounded-full bg-(--iux-muted)"
            role={progress ? "progressbar" : undefined}
            aria-valuemin={progress ? 0 : undefined}
            aria-valuemax={progress?.total}
            aria-valuenow={progress ? progress.step : undefined}
          >
            {progress ? (
              <div className="h-full rounded-full bg-[#f36c21] transition-[width] duration-500" style={{ width: `${(progress.step / progress.total) * 100}%` }} />
            ) : (
              <div className="h-full w-1/3 animate-pulse rounded-full bg-[#f36c21]" />
            )}
          </div>
        </div>
      ) : null}
      {current?.error ? <Status value={{ ok: false, text: current.error }} /> : null}
      {detail.error ? <Status value={{ ok: false, text: `Could not load job output: ${detail.error}` }} /> : null}
      {cancelError ? <Status value={{ ok: false, text: `Could not cancel job: ${cancelError}` }} /> : null}
      <div className="flex flex-wrap gap-2">
        {jobs.slice(0, 6).map((job) => (
          <button key={job.id} type="button" onClick={() => { setCancelError(null); onSelect(job.id); }}
            className="iux-btn" data-variant={job.id === id ? "primary" : "outline"}>
            {job.action} · {job.state}
          </button>
        ))}
        {current?.state === "running" ? (
          <button type="button" className="iux-btn" data-variant="outline" disabled={cancelling}
            onClick={async () => {
              setCancelling(true);
              setCancelError(null);
              try {
                await api.cancel(current.id);
                await jobsStore.refresh();
              } catch (e) {
                setCancelError(message(e));
              } finally {
                setCancelling(false);
              }
            }}>
            <StopIcon size={14} /> {cancelling ? "Cancelling…" : "Cancel job"}
          </button>
        ) : null}
      </div>
      <div>
        <p className="mb-2 text-xs font-medium text-(--iux-muted-foreground)">Output · {current?.lines ?? 0} lines</p>
        <pre className="max-h-80 overflow-auto rounded-lg border border-(--iux-border) bg-(--iux-muted) p-3 font-mono text-xs leading-relaxed whitespace-pre-wrap break-words">{logs.length ? logs.join("\n") : current?.state === "running" ? "Waiting for output…" : "No output."}</pre>
        {current?.truncated ? <p className="mt-1 text-xs text-(--iux-muted-foreground)">Earlier output was trimmed.</p> : null}
      </div>
    </div>
  );
}

function Monitor({ lab }: { lab: LabId }) {
  const { data, error, reload } = usePoll(() => api.monitor(lab), 10000, [lab]);
  return (
    <Section
      icon={<PulseIcon size={16} />}
      title="Live monitor"
      description={data?.runtime ? `Containers via ${data.runtime}, refreshed every 10 s.` : "Container state and resource use."}
      action={
        <button type="button" className="iux-btn" data-variant="outline" onClick={reload}>
          <ArrowClockwiseIcon size={14} /> Refresh
        </button>
      }
    >
      {error ? (
        <Status value={{ ok: false, text: error }} />
      ) : !data ? (
        <Skeleton rows={2} />
      ) : data.containers.length === 0 ? (
        <Empty>{data.note ?? "Nothing to monitor."}</Empty>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[36rem] text-left text-sm">
            <thead className="text-xs text-(--iux-muted-foreground)">
              <tr className="border-b border-(--iux-border)">
                <th className="py-2 pr-4 font-medium">Container</th>
                <th className="py-2 pr-4 font-medium">State</th>
                <th className="py-2 pr-4 font-medium">CPU</th>
                <th className="py-2 pr-4 font-medium">Memory</th>
                <th className="py-2 font-medium">Access</th>
              </tr>
            </thead>
            <tbody>
              {data.containers.map((c) => (
                <tr key={c.name} className="border-b border-(--iux-border) last:border-0">
                  <td className="py-2 pr-4 font-mono text-xs">{c.name}</td>
                  <td className="py-2 pr-4">
                    <Badge tone={c.state === "running" ? "success" : c.state === "absent" ? undefined : "warning"}>{c.state}</Badge>
                    <span className="ml-2 text-xs text-(--iux-muted-foreground)">{c.status}</span>
                  </td>
                  <td className="py-2 pr-4 tabular-nums">{c.cpu}</td>
                  <td className="py-2 pr-4 tabular-nums">{c.memory}</td>
                  <td className="py-2 font-mono text-xs">{c.ports || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Section>
  );
}

function Configuration({ lab, ready, onProfile }: { lab: LabId; ready: boolean; onProfile: (profile: string) => void }) {
  const { data, error } = usePoll(() => api.config(lab), 0, [lab]);
  return (
    <details className="iux-card group p-5">
      <summary className="flex cursor-pointer list-none items-center gap-2 text-sm font-semibold [&::-webkit-details-marker]:hidden">
        <GearSixIcon size={16} className="text-[#f36c21]" />
        Advanced settings
        <span aria-hidden="true" className="ml-auto text-(--iux-muted-foreground) transition-transform group-open:rotate-90">›</span>
      </summary>
      <div className="mt-4 flex flex-col gap-4">
        {error ? <Status value={{ ok: false, text: error }} /> : null}
        {!data && !error ? <Skeleton rows={2} /> : null}
        {data && ready && data.endpoints.length ? (
          <Section icon={<PlayIcon size={16} />} title="Endpoints" description="Addresses from the lab's configuration; they answer once the lab is running.">
            <EndpointList items={data.endpoints} />
          </Section>
        ) : null}
        {data ? (
          <Section
            icon={<GearSixIcon size={16} />}
            title="Configuration"
            description={
              <>
                <code>{data.path}</code> {data.exists ? "" : "(not created yet — defaults from the example file)"}. Secrets are masked.
              </>
            }
          >
            <div className="flex flex-col gap-4">
              {data.profiles.length ? (
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm font-medium">Profiles</span>
                  {data.profiles.map((p) => (
                    <button key={p} type="button" className="iux-btn" data-variant="outline" onClick={() => onProfile(p)} title={`Preview applying ${p}`}>
                      {p}
                    </button>
                  ))}
                </div>
              ) : null}
              <details>
                <summary className="cursor-pointer text-sm">{data.fields.length} settings</summary>
                <ul className="mt-3 max-h-80 overflow-y-auto text-xs">
                  {data.fields.map((f) => (
                    <li key={f.key} className="flex gap-3 border-b border-(--iux-border) py-1.5">
                      <span className="w-48 shrink-0 truncate font-mono">{f.key}</span>
                      <span className="min-w-0 flex-1 truncate font-mono text-(--iux-muted-foreground)">{f.value || "—"}</span>
                      {f.local ? <Badge>.env</Badge> : null}
                    </li>
                  ))}
                </ul>
              </details>
            </div>
          </Section>
        ) : null}
      </div>
    </details>
  );
}

export default function LabPage({ lab: labId }: { lab: LabId }) {
  if (import.meta.env.PUBLIC_SITE_MODE === "pages" && labId === "source") {
    return <AppShell activeId="lab-source"><TopBar title="Source Lab" icon={LAB_ICON.source(20)} />
      <main className="mx-auto max-w-4xl p-8"><PageHead icon={LAB_ICON.source(22)} title="Source Lab"
        description="Runs locally with Python 3.11+. Open the installed console to check readiness and run analyses." />
        <a className="iux-btn mt-6" href="https://github.com/keyvanarasteh/os-lab/tree/master/source-lab">Repository</a>
      </main></AppShell>;
  }
  return <LiveLabPage lab={labId} />;
}

function LiveLabPage({ lab: labId }: { lab: LabId }) {
  const { data: hostData, error: hostError, refresh: refreshHost } = hostStore.use();
  const { data: allJobs } = jobsStore.use();
  const lab = hostData?.labs.find((l) => l.id === labId);
  const host = hostData?.host;
  const jobs = useMemo(() => (allJobs ?? []).filter((j) => j.lab === labId), [allJobs, labId]);
  const [request, setRequest] = useState<LabRequest | null>(null);
  const [plan, setPlan] = useState<{ plan: LabPlan; token: string } | null>(null);
  const [planError, setPlanError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  const [selectedJob, setSelectedJob] = useState<string | null>(null);
  const [distro, setDistro] = useState("");
  const [resize, setResize] = useState({ cpus: "", ram: "", disk: "", device: "" });

  const preview = async (action: string, extra: Partial<LabRequest> = {}) => {
    const req: LabRequest = { lab: labId, action, ...extra };
    if (lab?.provider === "wsl2") req.wslDistro = distro || host?.wsl.distributions[0];
    setRequest(req);
    setPlan(null);
    setPlanError(null);
    requestAnimationFrame(() => document.getElementById("plan")?.scrollIntoView({ behavior: "smooth", block: "start" }));
    try {
      setPlan(await api.plan(req));
    } catch (e) {
      setPlanError(message(e));
    }
  };
  const run = async () => {
    if (!request || !plan) return;
    setStarting(true);
    try {
      const job = await api.start(request, plan.token);
      setSelectedJob(job.id);
      setRequest(null);
      setPlan(null);
      await jobsStore.refresh();
      requestAnimationFrame(() => document.getElementById("jobs")?.scrollIntoView({ behavior: "smooth", block: "start" }));
    } catch (e) {
      setPlanError(message(e));
    } finally {
      setStarting(false);
    }
  };

  // Deep links from the host page and Spotlight: #action=setup previews that action
  useEffect(() => {
    if (!lab) return;
    const m = /action=([a-z-]+)/.exec(window.location.hash);
    if (m && lab.actions.some((a) => a.id === m[1])) {
      history.replaceState(null, "", window.location.pathname);
      void preview(m[1]);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lab?.id, lab?.actions.length]);

  // Re-detect the host when a job on this lab finishes (setup may have fixed a requirement)
  const runningCount = jobs.filter((j) => j.state === "running").length;
  useEffect(() => {
    if (runningCount === 0) void refreshHost();
  }, [runningCount, refreshHost]);

  const label = lab?.label ?? labId;
  const actions = new Map((lab?.actions ?? []).map((a) => [a.id, a]));
  const ref = REFERENCE[labId];
  // The ready iOS Simulator gets a device frame panel instead of plain start/stop buttons.
  const simulator = labId === "ios" && lab?.provider === "native-macos" && lab.state === "ready";
  // Every tracked prerequisite is found: the card would only repeat success badges, so it yields
  // its half of the row to the actions. Anything missing keeps the full status list visible.
  const requirements = lab?.requirements ?? [];
  const depsInstalled = requirements.length > 0 && requirements.every((r) => r.found);

  return (
    <AppShell activeId={`lab-${labId}`}>
      <div className="iux min-h-screen">
        <TopBar title={labId === "android" ? "Android Lab · Runtime & Setup" : label} back={{ href: labId === "android" ? "/android/" : "/", label: labId === "android" ? "Android Lab" : "This computer" }} icon={LAB_ICON[labId](20)} />
        <main className="mx-auto flex max-w-6xl flex-col gap-8 px-4 py-8 sm:px-6">
          {!lab ? (
            hostError ? <Empty>Could not reach the lab engine: {hostError}</Empty> : <Skeleton rows={5} />
          ) : (
            <>
              <PageHead
                icon={LAB_ICON[labId](22)}
                title={label}
                description={lab.summary}
                actions={
                  <>
                    {stateBadge(lab.state)}
                    {lab.provider ? <Badge>{lab.provider}</Badge> : null}
                  </>
                }
              />

              {(lab.reasons.length > 0 || lab.notes.length > 0) && (
                <div className="space-y-1.5 rounded-xl border border-dashed border-(--iux-border) p-4 text-sm">
                  {lab.reasons.map((r) => (
                    <p key={r} className="flex gap-2">
                      <WarningCircleIcon size={16} className="mt-0.5 shrink-0 text-(--iux-warning)" /> {r}
                    </p>
                  ))}
                  {lab.notes.map((n) => (
                    <p key={n} className="flex gap-2 text-(--iux-muted-foreground)">
                      <InfoIcon size={16} className="mt-0.5 shrink-0" /> {n}
                    </p>
                  ))}
                </div>
              )}

              {request ? (
                <PlanPanel
                  title={`${actions.get(request.action)?.label ?? request.action} · ${label}`}
                  plan={plan?.plan ?? null}
                  busy={starting}
                  error={planError}
                  onRun={run}
                  onCancel={() => {
                    setRequest(null);
                    setPlan(null);
                    setPlanError(null);
                  }}
                />
              ) : null}

              {simulator ? <SimulatorPanel onPreview={(action, extra) => void preview(action, extra)} /> : null}

              {lab.state === "unavailable" ? (
                <Section title="Run it elsewhere" description={`On a supported host, these commands run from the os-lab checkout (${ref.where}).`}>
                  <div className="flex flex-col gap-3">
                    <ShellSnippet tabs={[{ id: "check", label: "check", command: ref.check }, { id: "start", label: "start", command: ref.setup }]} />
                  </div>
                </Section>
              ) : (
                <>
                  <div className="grid gap-6 lg:grid-cols-2">
                    {depsInstalled ? null : (
                      <Section
                        icon={<WrenchIcon size={16} />}
                        title="Dependencies"
                        description="What this lab needs on this computer."
                        action={
                          lab.requirements.some((r) => r.required && !r.found) && actions.has("setup") ? (
                            <button
                              type="button"
                              className={lab.state === "needs-setup" ? "iux-btn bg-[#f36c21] text-white hover:bg-[#fa7b32]" : "iux-btn"}
                              data-variant={lab.state === "needs-setup" ? undefined : "outline"}
                              onClick={() => void preview("setup")}
                            >
                              Install dependencies
                            </button>
                          ) : null
                        }
                      >
                        <Requirements lab={lab} onInstall={(action) => void preview(action)} />
                      </Section>
                    )}

                    <Section
                      className={depsInstalled ? "lg:col-span-2" : undefined}
                      icon={<PlayIcon size={16} />}
                      title="Actions"
                      description="Each action is previewed before it runs."
                    >
                      <div className="flex flex-col gap-4">
                        {lab.state === "needs-setup" ? (
                          <p className="text-xs text-(--iux-muted-foreground)">
                            Start, stop and the other actions appear once the missing dependencies are installed.
                          </p>
                        ) : null}
                        {lab.provider === "wsl2" ? (
                          <Field label="WSL2 distribution">
                            <select className="iux-input" value={distro} onChange={(e) => setDistro(e.target.value)}>
                              {(host?.wsl.distributions ?? []).map((d) => (
                                <option key={d}>{d}</option>
                              ))}
                            </select>
                          </Field>
                        ) : null}
                        {SEGMENT_GROUPS.map((group) => {
                          const items = group.ids
                            .filter((id) => !(simulator && (id === "start" || id === "stop")))
                            .map((id) => actions.get(id))
                            .filter(Boolean);
                          if (!items.length) return null;
                          return (
                            <div key={group.title}>
                              <p className="mb-2 text-xs font-medium text-(--iux-muted-foreground)">{group.title}</p>
                              {items.length === 1 ? (
                                // A lone segment (e.g. restart while the simulator panel owns start/stop) keeps a labelled button.
                                <button
                                  type="button"
                                  className="iux-btn"
                                  data-variant="outline"
                                  title={items[0]!.description}
                                  onClick={() => void preview(items[0]!.id)}
                                >
                                  {SEGMENT_ICON[items[0]!.id] ?? null} {items[0]!.label}
                                </button>
                              ) : (
                                <div role="group" aria-label={group.title} className="iux-seg">
                                  {items.map((a) => (
                                    <button
                                      key={a!.id}
                                      type="button"
                                      title={a!.description}
                                      aria-label={a!.label}
                                      data-primary={a!.id.endsWith("start") ? "true" : undefined}
                                      onClick={() => void preview(a!.id)}
                                    >
                                      {SEGMENT_ICON[a!.id] ?? <PlayIcon size={14} weight="fill" />}
                                      {a!.privileged ? <ShieldWarningIcon size={13} className="text-(--iux-warning)" /> : null}
                                    </button>
                                  ))}
                                </div>
                              )}
                            </div>
                          );
                        })}
                        {ACTION_GROUPS.map((group) => {
                          const items = group.ids.map((id) => actions.get(id)).filter(Boolean);
                          if (!items.length) return null;
                          return (
                            <div key={group.title}>
                              <p className="mb-2 text-xs font-medium text-(--iux-muted-foreground)">{group.title}</p>
                              <div className="flex flex-wrap gap-2">
                                {items.map((a) => (
                                  <button
                                    key={a!.id}
                                    type="button"
                                    className="iux-btn"
                                    data-variant="outline"
                                    title={a!.description}
                                    onClick={() => void preview(a!.id)}
                                  >
                                    {a!.label}
                                    {a!.privileged ? <ShieldWarningIcon size={13} className="text-(--iux-warning)" /> : null}
                                  </button>
                                ))}
                              </div>
                            </div>
                          );
                        })}
                        {actions.has("resize") ? (
                          <form
                            className="flex flex-wrap items-end gap-2"
                            onSubmit={(e) => {
                              e.preventDefault();
                              const extra = Object.fromEntries(Object.entries(resize).filter(([, v]) => v)) as Partial<LabRequest>;
                              void preview("resize", extra);
                            }}
                          >
                            <div className="w-20">
                              <Field label="CPUs">
                                <input className="iux-input" inputMode="numeric" value={resize.cpus} onChange={(e) => setResize({ ...resize, cpus: e.target.value })} placeholder="4" />
                              </Field>
                            </div>
                            <div className="w-24">
                              <Field label="RAM">
                                <input className="iux-input" value={resize.ram} onChange={(e) => setResize({ ...resize, ram: e.target.value })} placeholder="8G" />
                              </Field>
                            </div>
                            {labId === "windows" ? (
                              <div className="w-24">
                                <Field label="Disk">
                                  <input className="iux-input" value={resize.disk} onChange={(e) => setResize({ ...resize, disk: e.target.value })} placeholder="128G" />
                                </Field>
                              </div>
                            ) : null}
                            {labId === "android" ? (
                              <div className="w-48">
                                <Field label="Device">
                                  <input className="iux-input" value={resize.device} onChange={(e) => setResize({ ...resize, device: e.target.value })} placeholder="Samsung Galaxy S10" />
                                </Field>
                              </div>
                            ) : null}
                            <button type="submit" className="iux-btn" data-variant="outline">
                              Preview resize
                            </button>
                          </form>
                        ) : null}
                      </div>
                    </Section>
                  </div>

                  <section id="jobs" className="space-y-3">
                    <h2 className="text-sm font-semibold tracking-wider text-(--iux-muted-foreground) uppercase">Jobs</h2>
                    <JobPanel jobs={jobs} selected={selectedJob} onSelect={setSelectedJob} />
                  </section>

                  {lab.state === "ready" ? <Monitor lab={labId} /> : null}
                  <Configuration lab={labId} ready={lab.state === "ready"} onProfile={(p) => void preview("profile", { profile: p })} />
                </>
              )}
            </>
          )}
        </main>
      </div>
    </AppShell>
  );
}
