import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { Type } from "@sinclair/typebox";

type Mode = "on" | "off" | "none";

const DEFAULTS = {
  nyxBaseUrl: "http://127.0.0.1:8686",
  originalOpenrouterBaseUrl: "https://openrouter.ai/api/v1",
  sanitizedOpenrouterBaseUrl: "http://127.0.0.1:8686/openrouter",
};

async function callNyx(baseUrl: string, path: string, init?: RequestInit) {
  const res = await fetch(`${baseUrl}${path}`, init);
  const txt = await res.text();
  let body: any = {};
  try {
    body = JSON.parse(txt);
  } catch {
    body = { raw: txt };
  }
  if (!res.ok) {
    throw new Error(`Nyx API ${res.status}: ${txt}`);
  }
  return body;
}

function textReply(text: string) {
  return { content: [{ type: "text", text }] };
}

export default definePluginEntry({
  id: "nyx-guardrails-plugin",
  name: "Nyx Guardrails Plugin",
  description: "Commands for /ngr_sanitize and /ngr_dashboard",
  register(api) {
    const cfg = {
      nyxBaseUrl:
        (api as any).config?.nyxBaseUrl ?? DEFAULTS.nyxBaseUrl,
      originalOpenrouterBaseUrl:
        (api as any).config?.originalOpenrouterBaseUrl ?? DEFAULTS.originalOpenrouterBaseUrl,
      sanitizedOpenrouterBaseUrl:
        (api as any).config?.sanitizedOpenrouterBaseUrl ?? DEFAULTS.sanitizedOpenrouterBaseUrl,
    };

    api.registerCommand({
      name: "ngr_sanitize",
      description: "Toggle Nyx Guardrails sanitize mode: on/off/none",
      parameters: Type.Object({
        mode: Type.Union([Type.Literal("on"), Type.Literal("off"), Type.Literal("none")]),
      }),
      async execute(_id: string, params: { mode: Mode }) {
        const mode = params.mode;
        const status = await callNyx(cfg.nyxBaseUrl, `/ngr/admin/sanitize?mode=${mode}`, {
          method: "POST",
        });

        // Best-effort OpenClaw runtime URL update if runtime config mutators exist.
        const runtimeConfig = (api as any).runtime?.config;
        if (runtimeConfig && typeof runtimeConfig.set === "function") {
          if (mode === "on") {
            await runtimeConfig.set("providers.openrouter.baseUrl", cfg.sanitizedOpenrouterBaseUrl);
          } else if (mode === "off") {
            await runtimeConfig.set("providers.openrouter.baseUrl", cfg.originalOpenrouterBaseUrl);
          }
        }

        if (mode === "none") {
          return textReply(
            `ngr_sanitize status: ${status.sanitize_enabled ? "ON" : "OFF"}\n` +
              `nyxBaseUrl: ${cfg.nyxBaseUrl}\n` +
              `openrouter baseUrl (sanitized): ${cfg.sanitizedOpenrouterBaseUrl}\n` +
              `openrouter baseUrl (original): ${cfg.originalOpenrouterBaseUrl}`,
          );
        }

        return textReply(
          `ngr_sanitize ${mode.toUpperCase()} complete.\n` +
            `Nyx says: ${status.message}\n` +
            `If your OpenClaw build does not support runtime config mutation, set provider URL manually to:\n` +
            `${mode === "on" ? cfg.sanitizedOpenrouterBaseUrl : cfg.originalOpenrouterBaseUrl}`,
        );
      },
    });

    api.registerCommand({
      name: "ngr_dashboard",
      description: "Get one-time dashboard token URL and run warning scan",
      parameters: Type.Object({}),
      async execute() {
        const token = await callNyx(cfg.nyxBaseUrl, "/ngr/admin/dashboard-token");
        const scan = await callNyx(cfg.nyxBaseUrl, "/ngr/admin/file-scan", { method: "POST" });
        const url = `${cfg.nyxBaseUrl}/ngr/dashboard?token=${token.token}`;
        return textReply(
          `NGR dashboard URL:\n${url}\n\n` +
            `Warnings: ${scan.warnings}\nLast scan: ${scan.last_scan_at ?? "unknown"}\n` +
            `Token rotates on Nyx restart.`,
        );
      },
    });
  },
});
