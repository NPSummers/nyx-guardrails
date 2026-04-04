# Nyx Guardrails OpenClaw Plugin

This plugin exposes two OpenClaw commands that control a running `nyx-guardrails` proxy:

- `/ngr_sanitize on|off|none`
- `/ngr_dashboard`

## What it does

- `ngr_sanitize on`: enables sanitize mode in Nyx and attempts to switch OpenRouter base URL to Nyx.
- `ngr_sanitize off`: disables sanitize mode in Nyx and attempts to restore the original OpenRouter base URL.
- `ngr_sanitize none`: prints current sanitize status.
- `ngr_dashboard`: returns tokenized dashboard URL and runs warning-only file scan.

## Required Nyx endpoints

The plugin expects these local Nyx endpoints:

- `POST /ngr/admin/sanitize?mode=on|off|none`
- `GET /ngr/admin/dashboard-token`
- `POST /ngr/admin/file-scan`
- `GET /ngr/dashboard?token=...`

## Install

1. Keep `nyx-guardrails` running locally.
2. Install plugin package in OpenClaw.
3. Configure `nyxBaseUrl` if different from `http://127.0.0.1:8686`.
