import { createFileRoute } from "@tanstack/react-router";
import { Bell } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, Panel } from "@/components/tm/AppShell";
import { useApi } from "@/lib/use-api";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/alerts")({
  head: () => ({
    meta: [
      { title: "Alerts — ThreatMapper v2" },
      { name: "description", content: "Chronological feed of security alerts for your organization." },
      { property: "og:title", content: "Alerts — ThreatMapper v2" },
      { property: "og:description", content: "Chronological feed of security alerts for your organization." },
    ],
  }),
  component: AlertsPage,
});

interface AlertItem {
  id?: number | string;
  timestamp?: string;
  created_at?: string;
  ioc_value?: string;
  ioc?: string;
  ioc_type?: string;
  threat_score?: number;
  message?: string;
}

const scoreCls = (s: number) =>
  s >= 70 ? "bg-destructive/15 text-destructive border-destructive/40"
  : s >= 40 ? "bg-warning/15 text-warning border-warning/40"
  : "bg-success/15 text-success border-success/40";

function AlertsPage() {
  const { data, isLoading, error } = useApi<AlertItem[] | { alerts?: AlertItem[]; items?: AlertItem[] }>(["alerts"], "/api/alerts");
  const items = (Array.isArray(data) ? data : data?.alerts ?? data?.items ?? [])
    .slice()
    .sort((a, b) => +new Date(b.timestamp ?? b.created_at ?? 0) - +new Date(a.timestamp ?? a.created_at ?? 0));

  return (
    <Panel title="Alerts Inbox" className="max-w-4xl">
      {error ? <ErrorState message={(error as Error).message} /> : (
        <ul className="-m-4 divide-y divide-border">
          {isLoading && Array.from({ length: 6 }).map((_, i) => <li key={i} className="p-4"><Skeleton className="h-10 w-full" /></li>)}
          {!isLoading && items.length === 0 && (
            <li className="flex flex-col items-center gap-2 py-12 text-muted-foreground"><Bell className="h-6 w-6" />No alerts</li>
          )}
          {items.map((a, i) => {
            const s = Number(a.threat_score ?? 0);
            return (
              <li key={a.id ?? i} className="flex items-center gap-4 px-4 py-3 hover:bg-muted/40">
                <div className={cn("flex h-10 w-12 shrink-0 items-center justify-center rounded-sm border font-mono font-semibold", scoreCls(s))}>{s}</div>
                <div className="min-w-0 flex-1">
                  <div className="truncate font-mono">{a.ioc_value ?? a.ioc}</div>
                  {a.message && <div className="truncate text-xs text-muted-foreground">{a.message}</div>}
                </div>
                {a.ioc_type && <span className="rounded-sm bg-accent px-1.5 py-0.5 text-xs uppercase text-accent-foreground">{a.ioc_type}</span>}
                <time className="w-40 shrink-0 text-right text-xs text-muted-foreground">
                  {new Date(a.timestamp ?? a.created_at ?? "").toLocaleString()}
                </time>
              </li>
            );
          })}
        </ul>
      )}
    </Panel>
  );
}
