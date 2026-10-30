import { createFileRoute } from "@tanstack/react-router";
import { useState, type FormEvent } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Loader2, Plus } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { ErrorState, Panel } from "@/components/tm/AppShell";
import { IocTypeSelect, type IocType } from "@/components/tm/IocTypeSelect";
import { post } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useApi } from "@/lib/use-api";

export const Route = createFileRoute("/watchlist")({
  head: () => ({
    meta: [
      { title: "Watchlist — ThreatMapper v2" },
      { name: "description", content: "Monitored indicators of compromise for your organization." },
      { property: "og:title", content: "Watchlist — ThreatMapper v2" },
      { property: "og:description", content: "Monitored indicators of compromise for your organization." },
    ],
  }),
  component: WatchlistPage,
});

interface WatchItem {
  id?: number | string;
  ioc_value: string;
  ioc_type: string;
  added_at?: string;
  created_at?: string;
  last_checked?: string;
}

const fmt = (d?: string) => (d ? new Date(d).toLocaleString() : "—");

function WatchlistPage() {
  const { user } = useAuth();
  const qc = useQueryClient();
  const key = ["watchlist", user?.org_id];
  const { data, isLoading, error } = useApi<{ org_id: number; watchlist: WatchItem[] }>(
    key,
    user ? `/api/organizations/${user.org_id}/watchlist` : null,
  );
  const rows = data?.watchlist ?? [];

  const [open, setOpen] = useState(false);
  const [value, setValue] = useState("");
  const [type, setType] = useState<IocType>("ip");
  const [busy, setBusy] = useState(false);

  const add = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      const r = await post<{ status: string; message: string }>("/api/watchlist", { ioc_value: value.trim(), ioc_type: type, org_id: Number(user!.org_id) });
      if (r?.status === "info") toast.info(r.message);
      else toast.success(r?.message ?? "Added to watchlist");
      setOpen(false);
      setValue("");
      qc.invalidateQueries({ queryKey: key });
    } catch (err) {
      toast.error(`Failed to add: ${(err as Error).message}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <Panel
        title={`Monitored IOCs${rows.length ? ` (${rows.length})` : ""}`}
        action={<Button size="sm" onClick={() => setOpen(true)}><Plus className="h-4 w-4" />Add to Watchlist</Button>}
      >
        {error ? <ErrorState message={(error as Error).message} /> : (
          <div className="-m-4 overflow-x-auto">
            <table className="w-full text-left">
              <thead className="border-b border-border bg-muted/50 text-xs uppercase text-muted-foreground">
                <tr>
                  <th className="px-4 py-2 font-medium">IOC Value</th>
                  <th className="px-4 py-2 font-medium">Type</th>
                  <th className="px-4 py-2 font-medium">Added Date</th>
                  <th className="px-4 py-2 font-medium">Last Checked</th>
                </tr>
              </thead>
              <tbody>
                {isLoading && Array.from({ length: 5 }).map((_, i) => (
                  <tr key={i} className="border-b border-border"><td colSpan={4} className="px-4 py-2"><Skeleton className="h-5 w-full" /></td></tr>
                ))}
                {!isLoading && rows.length === 0 && (
                  <tr><td colSpan={4} className="px-4 py-10 text-center text-muted-foreground">No IOCs on the watchlist yet.</td></tr>
                )}
                {rows.map((r, i) => (
                  <tr key={r.id ?? i} className="border-b border-border hover:bg-muted/40">
                    <td className="px-4 py-2 font-mono">{r.ioc_value}</td>
                    <td className="px-4 py-2"><span className="rounded-sm bg-accent px-1.5 py-0.5 text-xs uppercase text-accent-foreground">{r.ioc_type}</span></td>
                    <td className="px-4 py-2 text-muted-foreground">{fmt(r.added_at ?? r.created_at)}</td>
                    <td className="px-4 py-2 text-muted-foreground">{fmt(r.last_checked)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent>
          <DialogHeader><DialogTitle>Add to Watchlist</DialogTitle></DialogHeader>
          <form onSubmit={add} className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="ioc">IOC value</Label>
              <Input id="ioc" className="font-mono" value={value} onChange={(e) => setValue(e.target.value)} required />
            </div>
            <div className="space-y-1.5">
              <Label>Type</Label>
              <IocTypeSelect value={type} onChange={setType} />
            </div>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setOpen(false)}>Cancel</Button>
              <Button type="submit" disabled={busy}>{busy && <Loader2 className="h-4 w-4 animate-spin" />}Add</Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </>
  );
}
