<!-- LOVABLE:BEGIN -->
> [!IMPORTANT]
> This project is connected to [Lovable](https://lovable.dev). Avoid rewriting
> published git history — force pushing, or rebasing/amending/squashing commits
> that are already pushed — as it rewrites history on Lovable's side and the
> user will likely lose their project history.
>
> Commits you push to the connected branch sync back to Lovable and show up in
> the editor, so keep the branch in a working state.
<!-- LOVABLE:END -->

## Architecture
- All data comes from the external FastAPI backend via `src/lib/api.ts` (JWT from localStorage "token" on every request, no mock/demo data); page types mirror the response shapes in the user's main.py; base URL from `VITE_API_BASE_URL`. Why: backend is user-owned, not Lovable Cloud.
- Auth state lives in `src/lib/auth.tsx`; `__root.tsx` wraps every route except `/login` in `AppShell`, which redirects signed-out users client-side. Why: token is in localStorage, unavailable during SSR.
