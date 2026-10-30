import { createFileRoute } from "@tanstack/react-router";
import { Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Activity, AlertTriangle, Database, Layers } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, Panel } from "@/components/tm/AppShell";
import { useApi } from "@/lib/use-api";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Dashboard — ThreatMapper v2" },
      { name: "description", content: "Overview of monitored IOCs and threat correlation across your organization." },
      { property: "og:title", content: "Dashboard — ThreatMapper v2" },
      { property: "og:description", content: "Overview of monitored IOCs and threat correlation across your organization." },
    ],
  }),
  component: Dashboard,
});

// Matches GET /api/correlation in main.py
interface Correlation {
  org_id: number;
  total_monitored: number;
  distribution: Record<string, number>;
}

const COLORS = ["var(--chart-1)", "var(--chart-2)", "var(--chart-3)", "var(--chart-4)", "var(--chart-5)"];

function Dashboard() {
  const { data, isLoading, error } = useApi<Correlation>(["correlation"], "/api/correlation");

  const alerts = useApi<unknown[] | { alerts?: unknown[] }>(["alerts"], "/api/alerts");
  const dist = Object.entries(data?.distribution ?? {}).map(([name, value]) => ({ name, value: Number(value) }));
  const total = data?.total_monitored ?? 0;
  const alertCount = Array.isArray(alerts.data) ? alerts.data.length : alerts.data?.alerts?.length;
  const top = dist.slice().sort((a, b) => b.value - a.value)[0];

  const metrics = [
    { label: "Total Monitored IOCs", value: total, icon: Database },
    { label: "IOC Types", value: dist.length, icon: Layers },
    { label: "Top IOC Type", value: top ? top.name.toUpperCase() : "—", icon: AlertTriangle },
    { label: "Alerts", value: alertCount ?? "—", icon: Activity },
  ];

  if (error) return <ErrorState message={`Failed to load correlation data: ${(error as Error).message}`} />;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {metrics.map((m) => (
          <div key={m.label} className="rounded-sm border border-border bg-card p-4">
            <div className="flex items-center justify-between text-xs uppercase tracking-wide text-muted-foreground">
              {m.label}
              <m.icon className="h-4 w-4 text-primary" />
            </div>
            {isLoading ? <Skeleton className="mt-2 h-8 w-20" /> : <div className="mt-1 text-2xl font-semibold">{m.value}</div>}
          </div>
        ))}
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="IOC Type Distribution">
          {isLoading ? <Skeleton className="h-64 w-full" /> : dist.length === 0 ? <Empty /> : (
            <ResponsiveContainer width="100%" height={260}>
              <PieChart>
                <Pie data={dist} dataKey="value" nameKey="name" innerRadius={60} outerRadius={100} stroke="var(--card)">
                  {dist.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
                </Pie>
                <Tooltip contentStyle={{ background: "var(--popover)", border: "1px solid var(--border)", fontSize: 12 }} />
              </PieChart>
            </ResponsiveContainer>
          )}
        </Panel>
        <Panel title="IOCs by Type">
          {isLoading ? <Skeleton className="h-64 w-full" /> : dist.length === 0 ? <Empty /> : (
            <ResponsiveContainer width="100%" height={260}>
              <BarChart data={dist}>
                <CartesianGrid stroke="var(--border)" vertical={false} />
                <XAxis dataKey="name" stroke="var(--muted-foreground)" fontSize={12} />
                <YAxis stroke="var(--muted-foreground)" fontSize={12} allowDecimals={false} />
                <Tooltip cursor={{ fill: "var(--muted)" }} contentStyle={{ background: "var(--popover)", border: "1px solid var(--border)", fontSize: 12 }} />
                <Bar dataKey="value" fill="var(--chart-1)" radius={[2, 2, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </Panel>
      </div>
    </div>
  );
}

function Empty() {
  return <div className="flex h-64 items-center justify-center text-muted-foreground">No data yet</div>;
}
