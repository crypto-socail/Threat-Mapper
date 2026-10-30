import { createFileRoute } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useState, type FormEvent } from "react";
import { Loader2, Save } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Panel } from "@/components/tm/AppShell";
import { post } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useApi } from "@/lib/use-api";

export const Route = createFileRoute("/settings")({
  head: () => ({
    meta: [
      { title: "SIEM Settings — ThreatMapper v2" },
      { name: "description", content: "Configure the SIEM integration for your organization." },
      { property: "og:title", content: "SIEM Settings — ThreatMapper v2" },
      { property: "og:description", content: "Configure the SIEM integration for your organization." },
    ],
  }),
  component: SettingsPage,
});

// Matches SiemConfigCreate / GET /api/organizations/{org_id}/siem/config in main.py
interface SiemConfig {
  siem_type: string;
  endpoint_url?: string | null;
  auth_token?: string;
  sync_mode: string;
  updated_at?: string;
}
interface SiemConfigList {
  org_id: number;
  configs: SiemConfig[];
}

function SettingsPage() {
  const { user } = useAuth();
  const path = user ? `/api/organizations/${user.org_id}/siem/config` : null;
  const { data, isLoading } = useApi<SiemConfigList>(["siem", user?.org_id], path);
  const qc = useQueryClient();
  const [form, setForm] = useState<SiemConfig>({ siem_type: "splunk", endpoint_url: "", auth_token: "", sync_mode: "push" });
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const existing = data?.configs?.find((c) => c.siem_type === form.siem_type) ?? data?.configs?.[0];
    if (existing) setForm((f) => ({ ...f, ...existing, endpoint_url: existing.endpoint_url ?? "", auth_token: "" }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data]);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      const r = await post<{ message: string }>(path!, {
        siem_type: form.siem_type,
        endpoint_url: form.endpoint_url?.trim() || null,
        auth_token: form.auth_token,
        sync_mode: form.sync_mode,
      });
      toast.success(r?.message ?? "SIEM configuration saved");
      setForm((f) => ({ ...f, auth_token: "" }));
      qc.invalidateQueries({ queryKey: ["siem", user?.org_id] });
    } catch (err) {
      toast.error(`Save failed: ${(err as Error).message}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Panel title="SIEM Integration" className="max-w-2xl">
      {isLoading ? (
        <div className="space-y-4">{[0, 1, 2].map((i) => <Skeleton key={i} className="h-9 w-full" />)}</div>
      ) : (
        <form onSubmit={submit} className="space-y-4">
          <div className="space-y-1.5">
            <Label>SIEM Type</Label>
            <Select value={form.siem_type} onValueChange={(v) => setForm({ ...form, siem_type: v })}>
              <SelectTrigger className="w-48"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="splunk">Splunk</SelectItem>
                <SelectItem value="wazuh">Wazuh</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="ep">Endpoint URL (optional for pull mode)</Label>
            <Input id="ep" type="url" placeholder="https://splunk.example.com:8088/services/collector"
              value={form.endpoint_url ?? ""} onChange={(e) => setForm({ ...form, endpoint_url: e.target.value })} />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="tok">Auth Token</Label>
            <Input id="tok" type="password" className="font-mono" placeholder={data?.configs?.length ? "Re-enter token to save changes" : ""}
              value={form.auth_token ?? ""} onChange={(e) => setForm({ ...form, auth_token: e.target.value })} required />
          </div>
          <div className="space-y-1.5">
            <Label>Sync Mode</Label>
            <Select value={form.sync_mode} onValueChange={(v) => setForm({ ...form, sync_mode: v })}>
              <SelectTrigger className="w-48"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="push">Push</SelectItem>
                <SelectItem value="pull">Pull (live feed)</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="flex justify-end border-t border-border pt-4">
            <Button type="submit" disabled={busy}>
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}Save configuration
            </Button>
          </div>
        </form>
      )}
    </Panel>
  );
}
