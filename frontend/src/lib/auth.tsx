import type React from "react";
import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { toast } from "sonner";
import { post } from "./api";

export interface User {
  username: string;
  role: string;
  org_id: string;
}

interface AuthCtx {
  user: User | null;
  ready: boolean;
  login: (username: string, password: string) => Promise<void>;
  register: (input: RegisterInput) => Promise<void>;
  logout: () => void;
}

// Keep one context instance across hot reloads so provider and consumers never diverge.
const g = globalThis as unknown as { __tmAuthCtx?: React.Context<AuthCtx | null> };
const Ctx = (g.__tmAuthCtx ??= createContext<AuthCtx | null>(null));

export interface RegisterInput {
  username: string;
  password: string;
  org_id: number;
  email?: string | undefined;
}

interface LoginResponse {
  access_token: string;
  org_id: string | number;
  role?: string;
  username?: string;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    const token = localStorage.getItem("token");
    const raw = localStorage.getItem("user");
    if (token && raw) {
      try {
        setUser(JSON.parse(raw));
      } catch {
        /* ignore */
      }
    }
    setReady(true);
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem("token");
    localStorage.removeItem("org_id");
    localStorage.removeItem("user");
    setUser(null);
  }, []);

  useEffect(() => {
    const onUnauth = () => {
      if (localStorage.getItem("token")) toast.error("Session expired. Please sign in again.");
      logout();
    };
    window.addEventListener("tm:unauthorized", onUnauth);
    return () => window.removeEventListener("tm:unauthorized", onUnauth);
  }, [logout]);

  const save = (res: LoginResponse, username: string) => {
    const u: User = {
      username: res.username ?? username,
      role: res.role ?? "analyst",
      org_id: String(res.org_id),
    };
    localStorage.setItem("token", res.access_token);
    localStorage.setItem("org_id", u.org_id);
    localStorage.setItem("user", JSON.stringify(u));
    setUser(u);
  };

  const login = async (username: string, password: string) => {
    const res = await post<LoginResponse>("/api/auth/login", { username, password });
    save(res, username);
  };

  const register = async (input: RegisterInput) => {
    const res = await post<LoginResponse>("/api/auth/register", input);
    save(res, input.username);
  };

  return <Ctx.Provider value={{ user, ready, login, register, logout }}>{children}</Ctx.Provider>;
}

export function useAuth() {
  const c = useContext(Ctx);
  if (!c) throw new Error("useAuth outside AuthProvider");
  return c;
}
