# PatrolLink Backend

Express.js API backend for the PatrolLink guard monitoring mobile application, built on PostgreSQL with Directus as the headless CMS and data layer.

## Architecture

- **Express.js** — REST API server
- **PostgreSQL (PostGIS)** — primary database
- **Directus** — headless CMS managing core data collections (users, patrols, assignments, logs, locations)
- **connect-pg-simple** — Express session store backed by PostgreSQL
- **Docker Compose** — runs postgres, directus, and express services

## Prerequisites

- Docker & Docker Compose
- Node.js (v18+) for local development

## Setup

1. **Configure Environment**
   ```bash
   cp .env.example .env
   ```
   Edit `.env` with your database, Directus, and JWT settings.

2. **Start Services**
   ```bash
   docker compose up -d
   ```
   This starts PostgreSQL, Directus (port 8057), and the Express API (port 5000).

3. **Directus Bootstrap** (first run only)
   The Directus container auto-migrates the schema on first startup using `snapshot.yaml`.

## Running Locally (without Docker)

```bash
npm install
npm run dev
```

Requires a running PostgreSQL instance with `DB_*` env vars configured.

## Project Structure

```
.
├── server.js                    # Express entry point (all routes)
├── snapshot.yaml                # Directus schema snapshot
├── docker-compose.yml           # Service orchestration
├── Dockerfile                   # Express container build
├── .env                         # Environment configuration
└── docker/
    ├── pgdata/                  # PostgreSQL data volume
    └── directus/
        ├── uploads/
        ├── extensions/
        └── templates/
```

## User Roles

- **guard** — manage own patrols and logs
- **supervisor** — view all patrols, manage guards
- **admin** — full access

## Key Features

- JWT + session-based authentication
- Real-time GPS patrol tracking via `gps_points` table
- Push notifications via admin_push_tokens
- Organization-based multi-tenancy via invite codes
- Periodic push notification scanning
