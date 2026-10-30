import { useQuery } from "@tanstack/react-query";
import { useEffect } from "react";
import { toast } from "sonner";
import { api } from "./api";
import { useAuth } from "./auth";

/** Client-side GET against the FastAPI backend; toasts on error. */
export function useApi<T>(key: unknown[], path: string | null) {
  const { user } = useAuth();
  const q = useQuery({
    queryKey: key,
    queryFn: () => api<T>(path!),
    enabled: !!user && !!path,
    retry: false,
  });
  useEffect(() => {
    if (q.error) toast.error((q.error as Error).message);
  }, [q.error]);
  return q;
}
