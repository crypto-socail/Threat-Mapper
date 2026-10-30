import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useState, type FormEvent } from "react";
import { Loader2 } from "lucide-react";
import logo from "@/assets/global-secora-logo.png.asset.json";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/lib/auth";

export const Route = createFileRoute("/login")({
  head: () => ({
    meta: [
      { title: "Sign in — ThreatMapper v2" },
      { name: "description", content: "Sign in to your ThreatMapper v2 threat intelligence workspace." },
      { property: "og:title", content: "Sign in — ThreatMapper v2" },
      { property: "og:description", content: "Sign in to your ThreatMapper v2 threat intelligence workspace." },
    ],
  }),
  component: LoginPage,
});

function LoginPage() {
  const { login, register } = useAuth();
  const navigate = useNavigate();
  const [mode, setMode] = useState<"login" | "register">("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [org, setOrg] = useState("");
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      if (mode === "login") await login(username, password);
      else await register({ username, password, org_id: Number(org), email: email.trim() || undefined });
      navigate({ to: "/" });
    } catch (err) {
      toast.error((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-sidebar px-4">
      <div className="w-full max-w-sm rounded-sm border border-border bg-card shadow-2xl">
        <div className="border-b border-border px-6 py-5 text-center">
          <img src={logo.url} alt="Global Secora Technology" className="mx-auto h-24 w-auto object-contain" />
          <div className="mt-3 text-lg font-semibold">ThreatMapper <span className="text-primary">v2</span></div>
          <p className="mt-1 text-xs text-muted-foreground">
            {mode === "login" ? "Sign in to your organization" : "Create an account"}
          </p>
        </div>
        <form onSubmit={submit} className="space-y-4 px-6 py-5">
          <div className="space-y-1.5">
            <Label htmlFor="u">Username</Label>
            <Input id="u" value={username} onChange={(e) => setUsername(e.target.value)} required autoComplete="username" />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="p">Password</Label>
            <Input id="p" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required autoComplete="current-password" />
          </div>
          {mode === "register" && (
            <div className="space-y-1.5">
              <Label htmlFor="o">Organization ID</Label>
              <Input id="o" type="number" min={1} value={org} onChange={(e) => setOrg(e.target.value)} required />
            </div>
          )}
          {mode === "register" && (
            <div className="space-y-1.5">
              <Label htmlFor="e">Email (optional)</Label>
              <Input id="e" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" />
            </div>
          )}
          <Button type="submit" className="w-full" disabled={busy}>
            {busy && <Loader2 className="h-4 w-4 animate-spin" />}
            {mode === "login" ? "Sign in" : "Register"}
          </Button>
          <button
            type="button"
            onClick={() => setMode(mode === "login" ? "register" : "login")}
            className="w-full text-center text-xs text-accent-foreground hover:underline"
          >
            {mode === "login" ? "No account? Register" : "Have an account? Sign in"}
          </button>
        </form>
      </div>
    </div>
  );
}
