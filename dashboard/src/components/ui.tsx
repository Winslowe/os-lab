/** Card and form primitives, ported from qLar's settings/ui.tsx. */
import type { ReactNode } from "react";
import { CheckCircleIcon, CopyIcon, CheckIcon, WarningCircleIcon } from "@phosphor-icons/react";
import { useState } from "react";

/** A settings card: title, optional description and action, then its body. */
export function Section({
  id,
  icon,
  title,
  description,
  action,
  className,
  children
}: {
  id?: string;
  icon?: ReactNode;
  title: string;
  description?: ReactNode;
  action?: ReactNode;
  className?: string;
  children: ReactNode;
}) {
  return (
    <section id={id} className={"iux-card gap-4 py-5" + (className ? ` ${className}` : "")}>
      <div className="flex flex-wrap items-start gap-3 px-5">
        <div className="min-w-0 flex-1">
          <h2 className="flex items-center gap-2 text-sm leading-none font-semibold">
            {icon ? <span className="text-[#f36c21]">{icon}</span> : null}
            {title}
          </h2>
          {description && <p className="mt-1.5 text-sm text-(--iux-muted-foreground)">{description}</p>}
        </div>
        {action}
      </div>
      <div className="px-5">{children}</div>
    </section>
  );
}

export function Field({ label, hint, children }: { label: string; hint?: ReactNode; children: ReactNode }) {
  return (
    <label className="flex min-w-0 flex-col gap-1.5 text-sm">
      <span className="font-medium">{label}</span>
      {children}
      {hint && <span className="text-xs text-(--iux-muted-foreground)">{hint}</span>}
    </label>
  );
}

/** Inline result of the last action in a card. */
export function Status({ value }: { value: { ok: boolean; text: string } | null }) {
  if (!value) return null;
  return (
    <p
      role={value.ok ? "status" : "alert"}
      className={`flex items-center gap-1.5 text-sm ${value.ok ? "text-(--iux-success)" : "text-(--iux-danger)"}`}
    >
      {value.ok ? <CheckCircleIcon size={14} /> : <WarningCircleIcon size={14} />}
      {value.text}
    </p>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return (
    <p className="rounded-md border border-dashed border-(--iux-border) px-3 py-5 text-center text-sm text-(--iux-muted-foreground)">
      {children}
    </p>
  );
}

export function Skeleton({ rows = 3 }: { rows?: number }) {
  return (
    <div className="flex flex-col gap-2" aria-busy="true">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="h-10 animate-pulse rounded-md bg-(--iux-muted)" />
      ))}
    </div>
  );
}

export type Tone = "success" | "warning" | "danger" | undefined;
export function Badge({ tone, children, title }: { tone?: Tone; children: ReactNode; title?: string }) {
  return (
    <span className="iux-badge" data-variant={tone ? undefined : "outline"} data-tone={tone} title={title}>
      {children}
    </span>
  );
}

/** Page heading row used under the top bar: icon + title + one-line description, actions on the right. */
export function PageHead({ icon, title, description, actions }: { icon: ReactNode; title: string; description: ReactNode; actions?: ReactNode }) {
  return (
    <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
      <div className="min-w-0 space-y-1">
        <div className="flex items-center gap-2">
          <span className="text-[#f36c21]">{icon}</span>
          <h1 className="text-xl font-bold tracking-tight text-(--iux-foreground)">{title}</h1>
        </div>
        <p className="text-xs text-(--iux-muted-foreground)">{description}</p>
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [state, setState] = useState<"idle" | "copying" | "copied" | "failed">("idle");
  return (
    <span className="relative inline-flex shrink-0">
      <button
        type="button"
        data-size="icon"
        disabled={state === "copying"}
        aria-label={label}
        title={label}
        className="iux-touch-target flex size-7 items-center justify-center rounded-md border border-(--iux-border)/80 text-(--iux-muted-foreground) transition-colors hover:bg-(--iux-muted) hover:text-(--iux-foreground)"
        onClick={async () => {
          setState("copying");
          try {
            await navigator.clipboard.writeText(text);
            setState("copied");
            setTimeout(() => setState(current => current === "copied" ? "idle" : current), 2000);
          } catch {
            setState("failed");
          }
        }}
      >
        {state === "copied" ? <CheckIcon size={14} className="text-[#00d084]" weight="bold" /> : <CopyIcon size={14} />}
      </button>
      {state === "copied" || state === "failed" ? <span role="status" className="absolute right-0 top-full z-10 mt-1 w-48 rounded-md border border-(--iux-border) bg-(--iux-card) p-2 text-xs text-(--iux-foreground) shadow-lg">{state === "copied" ? "Copied" : "Clipboard unavailable. Select the text manually."}</span> : null}
    </span>
  );
}

/** Address rows: URLs open in a new tab, everything else copies. */
export function EndpointList({ items }: { items: { label: string; address: string }[] }) {
  return (
    <ul className="divide-y divide-(--iux-border)">
      {items.map((item) => (
        <li key={item.label} className="flex items-center gap-3 py-2.5">
          <span className="w-28 shrink-0 text-xs text-(--iux-muted-foreground)">{item.label}</span>
          <span className="min-w-0 flex-1 truncate font-mono text-[13px]">{item.address}</span>
          {/^https?:/.test(item.address) ? (
            <a className="iux-btn" data-variant="ghost" href={item.address} target="_blank" rel="noreferrer">
              Open
            </a>
          ) : (
            <CopyButton text={item.address} label={`Copy ${item.label}`} />
          )}
        </li>
      ))}
    </ul>
  );
}
