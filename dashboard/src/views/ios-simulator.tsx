/**
 * iOS Lab simulator panel: pick an installed device, attach (boot) it and watch its screen here.
 * Attach and detach stay previewed lab actions (start with a device option, stop), so nothing
 * runs without confirmation; the screen is the booted device's screenshot via the console.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowClockwiseIcon,
  CameraIcon,
  CircleNotchIcon,
  DeviceMobileIcon,
  FrameCornersIcon,
  PowerIcon
} from "@phosphor-icons/react";
import { Badge, Empty, Field, Section, Skeleton, Status } from "../components/ui";
import { api, message, usePoll, type LabRequest } from "../lib/api";

/** Screens refresh a little slower than jobs; each frame is one simctl screenshot on this Mac. */
const SCREEN_INTERVAL = 5000;

export function SimulatorPanel({ onPreview }: { onPreview: (action: string, extra?: Partial<LabRequest>) => void }) {
  const { data, error } = usePoll(() => api.iosSimulator(), SCREEN_INTERVAL);
  const [udid, setUdid] = useState("");
  const [framed, setFramed] = useState(true);
  // An older console (or the e2e mock) may answer {}; every field is optional in practice.
  const devices = data?.devices ?? [];
  const booted = data?.booted?.[0] ?? null;

  // The picker starts on the booted device, else the configured one, else the first iPhone.
  const defaultUdid = useMemo(
    () =>
      booted?.udid ??
      (data?.configuredDevice ? devices.find((d) => d.name === data.configuredDevice)?.udid : undefined) ??
      devices.find((d) => d.name.startsWith("iPhone"))?.udid ??
      devices[0]?.udid ??
      "",
    [booted?.udid, data?.configuredDevice, devices]
  );
  useEffect(() => {
    if (defaultUdid && !devices.some((d) => d.udid === udid)) setUdid(defaultUdid);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [defaultUdid]);

  const selected = devices.some((d) => d.udid === udid) ? udid : defaultUdid;
  const attach = () => onPreview("start", selected ? { device: selected } : {});
  const detach = () => onPreview("stop");

  const [shot, setShot] = useState<string | null>(null);
  const [shotError, setShotError] = useState<string | null>(null);
  const [shotBusy, setShotBusy] = useState(false);
  const shotRef = useRef<string | null>(null);
  const grab = useCallback(async () => {
    setShotBusy(true);
    try {
      const res = await fetch(api.iosScreenshotUrl, { cache: "no-store" });
      if (!res.ok) {
        const body = (await res.json().catch(() => ({}))) as { error?: string };
        throw new Error(body.error || `${res.status} ${res.statusText}`);
      }
      const url = URL.createObjectURL(await res.blob());
      if (shotRef.current) URL.revokeObjectURL(shotRef.current);
      shotRef.current = url;
      setShot(url);
      setShotError(null);
    } catch (e) {
      setShotError(message(e));
    } finally {
      setShotBusy(false);
    }
  }, []);
  useEffect(() => () => {
    if (shotRef.current) URL.revokeObjectURL(shotRef.current);
  }, []);
  useEffect(() => {
    if (!booted) {
      setShot(null);
      setShotError(null);
      return;
    }
    void grab();
    const timer = setInterval(() => {
      if (!document.hidden) void grab();
    }, SCREEN_INTERVAL);
    return () => clearInterval(timer);
  }, [booted?.udid, grab]);

  return (
    <Section
      icon={<DeviceMobileIcon size={16} />}
      title="Simulator"
      description="Pick a device, attach it and watch its screen here."
    >
      {error ? (
        <Status value={{ ok: false, text: error }} />
      ) : !data ? (
        <Skeleton rows={2} />
      ) : !data.available ? (
        <Empty>{data.reason ?? "The simulator tooling is not usable on this Mac."}</Empty>
      ) : (
        <div className="flex flex-col items-center gap-5">
          <div className="flex w-full max-w-sm flex-wrap items-center justify-between gap-3">
            <div className="min-w-56 flex-1">
              <Field label="Device" hint={data.runtimes[0]}>
                <select className="iux-input" value={selected} onChange={(e) => setUdid(e.target.value)} aria-label="Device">
                  {devices.map((d) => (
                    <option key={d.udid} value={d.udid}>
                      {d.name} · {d.runtime}
                    </option>
                  ))}
                </select>
              </Field>
            </div>
            {booted ? (
              <Badge tone="success">
                Booted{` · ${booted.name}`}
              </Badge>
            ) : null}
          </div>

          <div className={`relative ${framed ? "rounded-[3rem] border border-zinc-700 bg-zinc-950 p-2 shadow-[0_25px_60px_-15px_rgba(0,0,0,0.55)]" : ""}`}>
            {framed ? (
              <>
                <span aria-hidden="true" className="absolute top-24 -left-[3px] h-9 w-[3px] rounded-l-sm bg-zinc-600" />
                <span aria-hidden="true" className="absolute top-36 -left-[3px] h-12 w-[3px] rounded-l-sm bg-zinc-600" />
                <span aria-hidden="true" className="absolute top-28 -right-[3px] h-16 w-[3px] rounded-r-sm bg-zinc-600" />
              </>
            ) : null}
            <div
              className={`relative w-72 max-w-full overflow-hidden bg-black ${framed ? "rounded-[2.6rem]" : "rounded-xl border border-(--iux-border)"}`}
              style={{ aspectRatio: "393 / 852" }}
            >
              {booted ? (
                shot ? (
                  <img src={shot} alt="Simulator screen" className="h-full w-full object-cover" />
                ) : shotError ? (
                  <div className="flex h-full flex-col items-center justify-center gap-3 p-6 text-center">
                    <p className="text-xs text-zinc-400">{shotError}</p>
                    <button type="button" className="iux-btn" data-variant="outline" onClick={() => void grab()}>
                      Retry
                    </button>
                  </div>
                ) : (
                  <div className="flex h-full items-center justify-center" aria-busy="true">
                    <CircleNotchIcon size={24} className="animate-spin text-zinc-500" aria-hidden />
                  </div>
                )
              ) : (
                <div className="flex h-full flex-col items-center justify-center gap-3 p-6 text-center">
                  <DeviceMobileIcon size={30} className="text-zinc-500" aria-hidden />
                  <p className="text-base font-semibold text-zinc-100">Attach a simulator to see its screen here</p>
                  <p className="text-xs text-zinc-400">Shut-down devices boot when you attach.</p>
                  <button
                    type="button"
                    className="mt-2 rounded-xl bg-white px-5 py-2.5 text-sm font-semibold text-black transition-colors hover:bg-zinc-200 disabled:opacity-60"
                    disabled={!devices.length}
                    onClick={attach}
                  >
                    Attach simulator
                  </button>
                </div>
              )}
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-center gap-2">
            <button type="button" className="iux-btn" data-variant="outline" aria-pressed={framed} onClick={() => setFramed((f) => !f)}>
              <FrameCornersIcon size={14} /> Frame
            </button>
            <button type="button" className="iux-btn" data-variant="outline" disabled={!booted || shotBusy} onClick={() => void grab()}>
              <ArrowClockwiseIcon size={14} /> Refresh
            </button>
            {shot ? (
              <a className="iux-btn" data-variant="outline" href={shot} download="ios-lab-screenshot.png">
                <CameraIcon size={14} /> Screenshot
              </a>
            ) : null}
            {booted ? (
              <button type="button" className="iux-btn" data-variant="outline" onClick={detach}>
                <PowerIcon size={14} /> Detach simulator
              </button>
            ) : null}
          </div>
        </div>
      )}
    </Section>
  );
}
