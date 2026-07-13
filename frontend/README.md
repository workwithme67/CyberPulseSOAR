# SOAR Incident Dashboard

A lightweight React + Vite frontend for the SOAR Incident Containment Engine.

## Features
- Live dashboard summary cards from `/dashboard/summary`
- Risk distribution bars from `/dashboard/risk-distribution`
- Recent alert feed from `/dashboard/recent-alerts`
- Auto-refresh every 15 seconds

## Run locally

```bash
npm install
npm run dev
```

By default the app talks to `http://localhost:8000` through Vite's proxy. To point it at another backend, set `VITE_API_BASE_URL` before starting Vite.
