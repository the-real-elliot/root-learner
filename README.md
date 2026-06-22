# Kali Academy

A web-based Kali Linux learning platform with interactive terminal lessons.

## Stack

- **Frontend**: React + Vite + Tailwind + shadcn/ui
- **Backend**: Express 5 + Node.js
- **Database**: PostgreSQL + Drizzle ORM
- **Monorepo**: pnpm workspaces

## Project Structure

```
artifacts/
  kali-academy/     # React frontend (Vite)
  api-server/       # Express backend
lib/
  db/               # Drizzle ORM schema + config
  api-spec/         # OpenAPI spec
  api-zod/          # Zod validation schemas
  api-client-react/ # Generated React Query hooks
```

## Local Development

```bash
# 1. Install dependencies
pnpm install

# 2. Set up environment
cp .env.example .env
# Edit .env with your DATABASE_URL

# 3. Push DB schema
cd lib/db && DATABASE_URL=... pnpm drizzle-kit push

# 4. Run backend
pnpm --filter @workspace/api-server run dev

# 5. Run frontend (new terminal)
BASE_PATH=/ PORT=5173 pnpm --filter @workspace/kali-academy run dev
```

## Deploy

This project is pre-configured for **Render** (backend) + **Supabase** (database).

See `render.yaml` for the full deploy config.

Set the `DATABASE_URL` environment variable in Render to your Supabase connection string.
