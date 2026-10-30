import { createFileRoute } from "@tanstack/react-router";
import { useState, type FormEvent } from "react";
import { Loader2, Search, ShieldAlert, ShieldCheck, ShieldQuestion } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Panel } from "@/components/tm/AppShell";
import { IocTypeSelect, type IocType } from "@/components/tm/IocTypeSelect";
import { post } from "@/lib/api";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/lookup")({
  head: () => ({
    meta: [
      { title: "Threat Lookup — ThreatMapper v2" },
      { name: "description", content: "Scan an IP, hash, domain or URL against threat intelligence sources." },
      { property: "og:title", content: "Threat Lookup — ThreatMapper v2" },
      { property: "og:description", content: "Scan an IP, hash, domain or URL against threat intelligence sources." },
    ],
  }),
  component: LookupPage,
});

interface LookupResult {
  verdict: string;
  confidence_score: number;
  sources_queried: string[];
  ioc: string;
  type: string;
}

const VERDICT = {
  malicious: { cls: "text-destructive border-destructive/50 bg-destructive/10", bar: "bg-destructive", icon: ShieldAlert },
  suspicious: { cls: "text-warning border-warning/50 bg-warning/10", bar: "bg-warning", icon: ShieldQuestion },
  clean: { cls: "text-success border-success/50 bg-success/10", bar: "bg-success", icon: ShieldCheck },
};

function LookupPage() {
  const [value, setValue] = useState("");
  const [type, setType] = useState<IocType>("ip");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<LookupResult | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setResult(null);
    try {
      setResult(await post<LookupResult>("/api/lookup", { ioc_value: value.trim(), ioc_type: type }));
    } catch (err) {
      toast.error(`Lookup failed: ${(err as Error).message}`);
    } finally {
      setBusy(false);
    }
  };

  const v = VERDICT[(result?.verdict?.toLowerCase() as keyof typeof VERDICT) ?? "clean"] ?? VERDICT.suspicious;
  const score = Math.max(0, Math.min(100, Number(result?.confidence_score ?? 0)));

  return (
    <div className="max-w-3xl space-y-4">
      <Panel title="Manual IOC Scanner">
        <form onSubmit={submit} className="flex flex-col gap-2 sm:flex-row">
          <Input
            placeholder="e.g. 185.220.101.4, evil.example.com, 44d88612fea8a8f36de82e1278abb02f"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            className="font-mono"
            required
          />
          <IocTypeSelect value={type} onChange={setType} />
          <Button type="submit" disabled={busy}>
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
            Scan
          </Button>
        </form>
      </Panel>

      {result && (
        <Panel title="Scan Result">
          <div className="grid gap-4 sm:grid-cols-3">
            <div className={cn("flex items-center gap-3 rounded-sm border p-4", v.cls)}>
              <v.icon className="h-8 w-8" />
              <div>
                <div className="text-xs uppercase opacity-80">Verdict</div>
                <div className="text-xl font-semibold capitalize">{result.verdict}</div>
              </div>
            </div>
            <div className="rounded-sm border border-border p-4">
              <div className="text-xs uppercase text-muted-foreground">Confidence</div>
              <div className="text-xl font-semibold">{Math.round(score)}<span className="text-sm text-muted-foreground">/100</span></div>
              <div className="mt-2 h-1.5 rounded-full bg-muted">
                <div className={cn("h-full rounded-full", v.bar)} style={{ width: `${score}%` }} />
              </div>
            </div>
            <div className="rounded-sm border border-border p-4">
              <div className="text-xs uppercase text-muted-foreground">Sources queried</div>
              <div className="mt-2 flex flex-wrap gap-1.5">
                {(result.sources_queried ?? []).map((s) => (
                  <span key={s} className="rounded-sm capitalize border border-border bg-accent px-2 py-0.5 text-xs text-accent-foreground">{s}</span>
                ))}
              </div>
            </div>
          </div>
          <div className="mt-3 font-mono text-xs text-muted-foreground">{(result.type ?? type).toUpperCase()} · <span className="break-all">{result.ioc ?? value}</span></div>
        </Panel>
      )}
    </div>
  );
}
