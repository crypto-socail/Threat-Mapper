import { Link, useNavigate, useRouterState } from "@tanstack/react-router";
import { useEffect, useState, type ReactNode } from "react";
import {
  Bell, ChevronRight, LayoutDashboard, ListChecks, LogOut, PanelLeftClose, PanelLeftOpen,
  Search, Settings, ShieldHalf, Building2, Loader2,
} from "lucide-react";
import { useAuth } from "@/lib/auth";
import { cn } from "@/lib/utils";
import logo from "@/assets/global-secora-logo.png.asset.json";

const NAV = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/lookup", label: "Threat Lookup", icon: Search },
  { to: "/watchlist", label: "Watchlist", icon: ListChecks },
  { to: "/alerts", label: "Alerts", icon: Bell },
  { to: "/settings", label: "SIEM Settings", icon: Settings },
] as const;

export function AppShell({ children }: { children: ReactNode }) {
  const { user, ready, logout } = useAuth();
  const navigate = useNavigate();
  const path = useRouterState({ select: (s) => s.location.pathname });
  const [collapsed, setCollapsed] = useState(false);

  useEffect(() => {
    if (ready && !user) navigate({ to: "/login" });
  }, [ready, user, navigate]);

  if (!ready || !user) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <Loader2 className="h-6 w-6 animate-spin text-primary" />
      </div>
    );
  }

  const current = NAV.find((n) => n.to === path) ?? NAV[0];

  return (
    <div className="flex h-screen w-full overflow-hidden bg-background">
      <aside
        className={cn(
          "flex shrink-0 flex-col border-r border-sidebar-border bg-sidebar text-sidebar-foreground transition-all",
          collapsed ? "w-14" : "w-60",
        )}
      >
        <div className="flex h-14 items-center gap-2 border-b border-sidebar-border px-3">
          {collapsed ? (
            <img src="/favicon.png" alt="Global Secora" className="h-7 w-7 shrink-0 object-contain" />
          ) : (
            <img src={logo.url} alt="Global Secora Technology" className="h-10 w-auto object-contain" />
          )}
        </div>
        <nav className="flex-1 space-y-0.5 p-2">
          {NAV.map((n) => {
            const active = n.to === path;
            return (
              <Link
                key={n.to}
                to={n.to}
                title={n.label}
                className={cn(
                  "flex items-center gap-3 rounded-sm border-l-2 px-3 py-2 transition-colors",
                  active
                    ? "border-primary bg-sidebar-accent text-sidebar-accent-foreground"
                    : "border-transparent hover:bg-sidebar-accent/60",
                )}
              >
                <n.icon className="h-4 w-4 shrink-0" />
                {!collapsed && <span>{n.label}</span>}
              </Link>
            );
          })}
        </nav>
        <div className="border-t border-sidebar-border p-2">
          {!collapsed && (
            <div className="mb-2 flex items-center gap-2 px-2 py-1">
              <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary text-xs font-semibold uppercase text-primary-foreground">
                {user.username.slice(0, 2)}
              </div>
              <div className="min-w-0">
                <div className="truncate font-medium">{user.username}</div>
                <div className="truncate text-xs capitalize text-muted-foreground">{user.role}</div>
              </div>
            </div>
          )}
          <button
            onClick={() => { logout(); navigate({ to: "/login" }); }}
            className="flex w-full items-center gap-3 rounded-sm px-3 py-2 text-muted-foreground hover:bg-sidebar-accent/60 hover:text-foreground"
            title="Logout"
          >
            <LogOut className="h-4 w-4 shrink-0" />
            {!collapsed && "Logout"}
          </button>
          <button
            onClick={() => setCollapsed((c) => !c)}
            className="flex w-full items-center gap-3 rounded-sm px-3 py-2 text-muted-foreground hover:bg-sidebar-accent/60 hover:text-foreground"
            title={collapsed ? "Expand" : "Collapse"}
          >
            {collapsed ? <PanelLeftOpen className="h-4 w-4" /> : <PanelLeftClose className="h-4 w-4" />}
            {!collapsed && "Collapse"}
          </button>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-12 shrink-0 items-center justify-between border-b border-border bg-card px-5">
          <div>
            <div className="flex items-center gap-1 text-xs text-muted-foreground">
              <span>Home</span>
              <ChevronRight className="h-3 w-3" />
              <span className="text-accent-foreground">{current.label}</span>
            </div>
            <h1 className="text-base font-semibold leading-tight">{current.label}</h1>
          </div>
          <div className="flex items-center gap-2 rounded-sm border border-border bg-muted px-2.5 py-1 font-mono text-xs">
            <Building2 className="h-3.5 w-3.5 text-primary" />
            <span className="text-muted-foreground">ORG</span>
            <span>{user.org_id}</span>
          </div>
        </header>
        <main className="flex-1 overflow-y-auto p-5">{children}</main>
      </div>
    </div>
  );
}

export function Panel({ title, action, children, className }: { title?: string; action?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={cn("rounded-sm border border-border bg-card", className)}>
      {title && (
        <div className="flex items-center justify-between border-b border-border px-4 py-2.5">
          <h2 className="text-sm font-semibold">{title}</h2>
          {action}
        </div>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function ErrorState({ message }: { message: string }) {
  return (
    <div className="rounded-sm border border-destructive/40 bg-destructive/10 px-4 py-3 text-sm text-destructive">
      {message}
    </div>
  );
}
