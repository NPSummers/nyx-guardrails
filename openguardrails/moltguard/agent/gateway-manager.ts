/**
 * AI Security Gateway Manager (Version 2)
 *
 * Strategy:
 * - Modify openclaw.json instead of agents star/agent/models.json
 * - Because ensureOpenClawModelsJson() overwrites models.json with openclaw.json
 */

import { existsSync, mkdirSync, writeFileSync, unlinkSync, readdirSync } from "node:fs";
import path from "node:path";
import os from "node:os";
import { spawn, spawnSync } from "node:child_process";
import { loadJsonSync } from "./fs-utils.js";

// =============================================================================
// Constants
// =============================================================================

const OPENCLAW_DIR = path.join(os.homedir(), ".openclaw");
const OPENCLAW_CONFIG = path.join(OPENCLAW_DIR, "openclaw.json");
const MOLTGUARD_DATA_DIR = path.join(OPENCLAW_DIR, "extensions/nyx-guardrails/data");
const GATEWAY_CONFIG = path.join(MOLTGUARD_DATA_DIR, "nyx-routing.json");
const GATEWAY_BACKUP = path.join(MOLTGUARD_DATA_DIR, "gateway-backup.json");
const DEFAULT_GATEWAY_PORT = Number(process.env.NYX_PORT || "8686");
const GATEWAY_SERVER_URL = process.env.NYX_BASE_URL || `http://127.0.0.1:${DEFAULT_GATEWAY_PORT}`;
const DEFAULT_NYX_CONFIG_PATH = path.join(os.homedir(), ".config", "nyx-guardrails", "nyx-guardrails.yaml");
const NYX_START_COMMAND =
  process.env.NYX_BACKEND_START_CMD || `nyx-guardrails --config "${DEFAULT_NYX_CONFIG_PATH}"`;
const NYX_WORKDIR = process.env.NYX_BACKEND_CWD || process.cwd();

// =============================================================================
// Auth Profiles (resolve API key placeholders like "VLLM_API_KEY")
// =============================================================================

type AuthProfile = {
  type: string;
  provider: string;
  key?: string;  // For api_key type
  access?: string;  // For oauth type
};

type AuthProfiles = {
  profiles: Record<string, AuthProfile>;
};

/**
 * Check if a string looks like an API key placeholder (e.g., "VLLM_API_KEY", "OPENAI_API_KEY")
 */
function isApiKeyPlaceholder(value: string): boolean {
  // Placeholder pattern: UPPERCASE_LETTERS with underscores, ending with _API_KEY or _KEY
  return /^[A-Z][A-Z0-9_]*(_API_KEY|_KEY)$/.test(value);
}

/**
 * Load auth-profiles.json for a specific agent
 */
function loadAuthProfiles(agentId: string = "main"): AuthProfiles | null {
  const authProfilesPath = path.join(OPENCLAW_DIR, "agents", agentId, "agent", "auth-profiles.json");
  try {
    if (existsSync(authProfilesPath)) {
      return loadJsonSync(authProfilesPath);
    }
  } catch {
    // Ignore errors
  }
  return null;
}

/**
 * Resolve API key from auth-profiles.json
 * @param providerName - Provider name (e.g., "vllm")
 * @param placeholder - The placeholder value (e.g., "VLLM_API_KEY")
 * @returns The actual API key, or the placeholder if not found
 */
function resolveApiKey(providerName: string, placeholder: string): string {
  // If not a placeholder, return as-is
  if (!isApiKeyPlaceholder(placeholder)) {
    return placeholder;
  }

  // Try to load auth profiles from main agent
  const authProfiles = loadAuthProfiles("main");
  if (!authProfiles?.profiles) {
    return placeholder;
  }

  // Look for matching profile (e.g., "vllm:default")
  const profileKey = `${providerName}:default`;
  const profile = authProfiles.profiles[profileKey];

  if (profile?.type === "api_key" && profile.key) {
    return profile.key;
  }

  // Also try just the provider name
  const directProfile = authProfiles.profiles[providerName];
  if (directProfile?.type === "api_key" && directProfile.key) {
    return directProfile.key;
  }

  return placeholder;
}

/**
 * Convert original baseUrl to Nyx provider route.
 */
function toGatewayUrl(providerName: string, provider?: ProviderConfig): string {
  const name = providerName.toLowerCase();
  const baseUrl = (provider?.baseUrl || "").toLowerCase();

  if (name.includes("openrouter") || baseUrl.includes("openrouter")) return `${GATEWAY_SERVER_URL}/openrouter`;
  if (name.includes("anthropic") || baseUrl.includes("anthropic")) return `${GATEWAY_SERVER_URL}/anthropic`;
  if (name.includes("google") || name.includes("gemini") || baseUrl.includes("google")) return `${GATEWAY_SERVER_URL}/google`;
  if (name.includes("xai") || name.includes("grok") || baseUrl.includes("x.ai")) return `${GATEWAY_SERVER_URL}/xai`;
  if (name.includes("deepseek") || baseUrl.includes("deepseek")) return `${GATEWAY_SERVER_URL}/deepseek`;
  if (name.includes("openai") || baseUrl.includes("openai")) return `${GATEWAY_SERVER_URL}/openai`;
  return `${GATEWAY_SERVER_URL}/openai`;
}

/**
 * Check if a baseUrl is pointing to Nyx.
 */
function isGatewayUrl(baseUrl: string): boolean {
  return baseUrl.startsWith(GATEWAY_SERVER_URL);
}

// =============================================================================
// Types
// =============================================================================

type OpenClawConfig = {
  models?: {
    mode?: string;
    providers?: Record<string, ProviderConfig>;
  };
  [key: string]: unknown;
};

type ProviderConfig = {
  baseUrl?: string;
  apiKey?: string;
  api?: string;
  models?: unknown[];
  [key: string]: unknown;
};

type GatewayBackup = {
  timestamp: string;
  routedProviders: Record<string, {
    originalBaseUrl: string;
  }>;
  agentModelsBackup?: Record<string, {
    files: string[];
    originalBaseUrls: Record<string, string>;
  }>;
};

type GatewayStatus = {
  enabled: boolean;
  running: boolean;
  port: number;
  url: string;
  providers: string[];
};

// =============================================================================
// Gateway Server Management
// =============================================================================

let gatewayRunning = false;
let dashboardPort: number | null = null;
let dashboardToken: string | null = null;

function killExistingNyxBackend(): void {
  if (process.platform === "win32") {
    spawnSync("taskkill", ["/IM", "nyx-guardrails.exe", "/F"], { stdio: "ignore", windowsHide: true });
    spawnSync("taskkill", ["/IM", "cargo.exe", "/F"], { stdio: "ignore", windowsHide: true });
    return;
  }
  spawnSync("pkill", ["-f", "nyx-guardrails"], { stdio: "ignore" });
  spawnSync("pkill", ["-f", "cargo run --release"], { stdio: "ignore" });
}

function startNyxBackend(): void {
  const child =
    process.platform === "win32"
      ? spawn("cmd.exe", ["/c", NYX_START_COMMAND], {
          cwd: NYX_WORKDIR,
          detached: true,
          stdio: "ignore",
          windowsHide: true,
          env: process.env,
        })
      : spawn("sh", ["-lc", NYX_START_COMMAND], {
          cwd: NYX_WORKDIR,
          detached: true,
          stdio: "ignore",
          env: process.env,
        });
  child.unref();
}

function ensureNyxBackendRunning(): void {
  killExistingNyxBackend();
  startNyxBackend();
}

/**
 * Set dashboard port for activity reporting
 */
export function setDashboardPort(port: number): void {
  dashboardPort = port;
}

/**
 * Set dashboard session token for authentication
 */
export function setDashboardToken(token: string): void {
  dashboardToken = token;
}

/**
 * Load dashboard session token from file
 */
function loadDashboardToken(): string | null {
  const tokenFile = path.join(OPENCLAW_DIR, "credentials", "nyx-guardrails", "dashboard-session-token");
  try {
    if (existsSync(tokenFile)) {
      const data = loadJsonSync<{ token?: string }>(tokenFile);
      return data.token || null;
    }
  } catch {
    // Ignore errors
  }
  return null;
}

/**
 * Report gateway activity to dashboard
 */
async function reportActivity(event: { [key: string]: unknown }): Promise<void> {
  if (!dashboardPort) {
    // Dashboard port not set, skip activity report
    return; // Dashboard not running, skip reporting
  }

  // Try to load token if not set
  if (!dashboardToken) {
    dashboardToken = loadDashboardToken();
  }

  if (!dashboardToken) {
    // Dashboard token not available, skip activity report
    return;
  }

  // Report activity silently

  try {
    const response = await fetch(`http://127.0.0.1:${dashboardPort}/api/gateway/activity`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${dashboardToken}`,
      },
      body: JSON.stringify(event),
    });

    if (!response.ok) {
      console.error("[nyx-guardrails] Failed to report activity:", response.status);
    }
  } catch {
    // Silently ignore errors - dashboard may not be running
  }
}

let activityListenerRegistered = false;

/** Optional callback for business reporter gateway activity */
let gatewayActivityCallback: ((redactionCount: number, typeCounts: Record<string, number>) => void) | null = null;

/** Set a callback to receive gateway activity events for business reporting */
export function setGatewayActivityCallback(cb: ((redactionCount: number, typeCounts: Record<string, number>) => void) | null): void {
  gatewayActivityCallback = cb;
}

/**
 * Check if a port is in use (TCP level check)
 */
async function isPortInUse(port: number): Promise<boolean> {
  const net = await import("node:net");
  return new Promise((resolve) => {
    const server = net.createServer();
    server.once("error", (err: NodeJS.ErrnoException) => {
      resolve(err.code === "EADDRINUSE");
    });
    server.once("listening", () => {
      server.close();
      resolve(false);
    });
    server.listen(port, "127.0.0.1");
  });
}

/**
 * Wait for a port to become available
 */
async function waitForPortAvailable(port: number, timeoutMs: number = 10000): Promise<boolean> {
  const startTime = Date.now();
  while (Date.now() - startTime < timeoutMs) {
    if (!(await isPortInUse(port))) return true;
    await new Promise(r => setTimeout(r, 500));
  }
  return false;
}

/**
 * Initialize Nyx routing state.
 */
export async function startGateway(): Promise<void> {
  mkdirSync(MOLTGUARD_DATA_DIR, { recursive: true });

  if (!existsSync(GATEWAY_CONFIG)) {
    const defaultConfig = {
      nyxBaseUrl: GATEWAY_SERVER_URL,
      routedBy: "nyx-guardrails-plugin",
    };
    writeFileSync(GATEWAY_CONFIG, JSON.stringify(defaultConfig, null, 2) + "\n", "utf-8");
  }
  // On plugin load/install, always restart Nyx backend to guarantee fresh routing target.
  ensureNyxBackendRunning();
  gatewayRunning = true;
}

/**
 * Reload Nyx routing state.
 */
export async function restartGateway(): Promise<void> {
  await stopGateway();
  await startGateway();
}

/**
 * Stop Nyx routing state.
 */
export async function stopGateway(): Promise<void> {
  gatewayRunning = false;
}

export function isGatewayRunning(): boolean {
  return gatewayRunning;
}

// =============================================================================
// Configuration Management
// =============================================================================

/**
 * Read openclaw.json
 */
function readOpenClawConfig(): OpenClawConfig {
  if (!existsSync(OPENCLAW_CONFIG)) {
    throw new Error("openclaw.json not found");
  }

  try {
    return loadJsonSync(OPENCLAW_CONFIG);
  } catch (err) {
    throw new Error(`Failed to parse openclaw.json: ${err}`);
  }
}

/**
 * Write openclaw.json
 */
function writeOpenClawConfig(config: OpenClawConfig): void {
  writeFileSync(OPENCLAW_CONFIG, JSON.stringify(config, null, 2) + "\n", "utf-8");
}

/**
 * Determine backend type from provider config
 */
function getBackendType(provider: ProviderConfig): string {
  if (provider.api === "anthropic") return "anthropic";
  if (provider.api === "gemini") return "gemini";
  if (provider.api === "openai-completions" || provider.api === "openai") return "openai";

  // Infer from baseUrl
  if (provider.baseUrl?.includes("anthropic.com")) return "anthropic";
  if (provider.baseUrl?.includes("gemini") || provider.baseUrl?.includes("google")) return "gemini";

  return "openai"; // Default
}

/**
 * Extract path from URL
 */
function extractPathFromUrl(urlString: string): string {
  try {
    const url = new URL(urlString);
    return url.pathname.endsWith("/") ? url.pathname.slice(0, -1) : url.pathname;
  } catch {
    return "";
  }
}

/**
 * Store provider metadata for Nyx routing bookkeeping.
 */
function configureGateway(providers: Record<string, ProviderConfig>): void {
  const backends: Record<string, { baseUrl: string; apiKey: string; type?: string; pathPrefix?: string; models?: string[] }> = {};

  for (const [name, provider] of Object.entries(providers)) {
    if (!provider.baseUrl || !provider.apiKey) continue;

    // Extract path prefix from original baseUrl for routing
    const pathPrefix = extractPathFromUrl(provider.baseUrl);

    // Extract model IDs from provider config
    const models = (provider.models as Array<{ id?: string }> | undefined)
      ?.map((m) => m.id)
      .filter((id): id is string => typeof id === "string");

    // Resolve API key placeholder (e.g., "VLLM_API_KEY" -> actual key from auth-profiles.json)
    const resolvedApiKey = resolveApiKey(name, provider.apiKey);
    if (resolvedApiKey !== provider.apiKey) {
      // Resolved API key placeholder
    }

    backends[name] = {
      baseUrl: provider.baseUrl,
      apiKey: resolvedApiKey,
      type: getBackendType(provider),
      ...(pathPrefix && { pathPrefix }),
      ...(models && models.length > 0 && { models }),
    };
  }

  const gatewayConfig = {
    port: DEFAULT_GATEWAY_PORT,
    backends,
  };

  mkdirSync(MOLTGUARD_DATA_DIR, { recursive: true });
  writeFileSync(GATEWAY_CONFIG, JSON.stringify(gatewayConfig, null, 2) + "\n", "utf-8");
}

/**
 * Find all agent models.json files
 */
function findAgentModelsFiles(): string[] {
  const agentsDir = path.join(OPENCLAW_DIR, "agents");
  const modelsFiles: string[] = [];

  if (!existsSync(agentsDir)) {
    return modelsFiles;
  }

  // Find all agent directories
  const entries = readdirSync(agentsDir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isDirectory()) {
      const modelsPath = path.join(agentsDir, entry.name, "agent", "models.json");
      if (existsSync(modelsPath)) {
        modelsFiles.push(modelsPath);
      }
    }
  }

  return modelsFiles;
}

/**
 * Read and parse a models.json file
 */
function readModelsJson(filePath: string): { providers?: Record<string, ProviderConfig> } | null {
  try {
    return loadJsonSync(filePath);
  } catch {
    return null;
  }
}

/**
 * Write a models.json file
 */
function writeModelsJson(filePath: string, data: unknown): void {
  writeFileSync(filePath, JSON.stringify(data, null, 2) + "\n", "utf-8");
}

/**
 * Update provider baseUrls in all agent models.json files.
 */
function updateAgentModelsFiles(backupData: Record<string, { files: string[]; originalBaseUrls: Record<string, string> }>): void {
  const modelsFiles = findAgentModelsFiles();

  for (const filePath of modelsFiles) {
    const data = readModelsJson(filePath);
    if (!data?.providers) continue;

    const fileBackup: Record<string, string> = {};
    let modified = false;

    for (const [name, provider] of Object.entries(data.providers)) {
      // Skip if already pointing to Nyx or no baseUrl
      if (!provider.baseUrl || isGatewayUrl(provider.baseUrl)) {
        continue;
      }
      fileBackup[name] = provider.baseUrl;
      provider.baseUrl = toGatewayUrl(name, provider);
      modified = true;
    }

    if (modified) {
      writeModelsJson(filePath, data);
      backupData[filePath] = {
        files: [filePath],
        originalBaseUrls: fileBackup,
      };
    }
  }
}

/**
 * Restore provider baseUrls in agent models.json files from backup
 */
function restoreAgentModelsFiles(backupData: Record<string, { files: string[]; originalBaseUrls: Record<string, string> }>): string[] {
  const restored: string[] = [];

  for (const [filePath, backup] of Object.entries(backupData)) {
    if (!existsSync(filePath)) continue;

    const data = readModelsJson(filePath);
    if (!data?.providers) continue;

    let modified = false;
    for (const [name, originalUrl] of Object.entries(backup.originalBaseUrls)) {
      if (data.providers[name]) {
        data.providers[name].baseUrl = originalUrl;
        modified = true;
      }
    }

    if (modified) {
      writeModelsJson(filePath, data);
      restored.push(filePath);
    }
  }

  return restored;
}

// =============================================================================
// Public API
// =============================================================================

/**
 * Enable Nyx routing.
 * Modifies openclaw.json to route all providers through Nyx.
 */
export async function enableGateway(): Promise<{ providers: string[]; warnings: string[] }> {
  // Check if already enabled
  if (existsSync(GATEWAY_BACKUP)) {
    throw new Error("Nyx routing is already enabled. Disable it first with '/nyx_sanitize off'");
  }

  // Read openclaw.json
  const config = readOpenClawConfig();
  if (!config.models?.providers) {
    throw new Error("No providers found in openclaw.json");
  }

  const providers = config.models.providers;
  const backup: GatewayBackup = {
    timestamp: new Date().toISOString(),
    routedProviders: {},
  };

  const routedProviders: string[] = [];
  const skipped: string[] = [];

  // Process each provider
  for (const [name, provider] of Object.entries(providers)) {
    // Skip if already pointing to Nyx
    if (provider.baseUrl && isGatewayUrl(provider.baseUrl)) {
      skipped.push(name);
      continue;
    }

    // Skip if no baseUrl
    if (!provider.baseUrl) {
      continue;
    }

    // Save original baseUrl (只保存 baseUrl，不保存整个配置)
    backup.routedProviders[name] = {
      originalBaseUrl: provider.baseUrl,
    };

    provider.baseUrl = toGatewayUrl(name, provider);
    routedProviders.push(name);
  }

  // If all providers are already pointing to Nyx, treat as "already enabled"
  if (routedProviders.length === 0 && skipped.length > 0) {
    // Create a minimal backup to mark Nyx routing as enabled
    mkdirSync(MOLTGUARD_DATA_DIR, { recursive: true });
    const minimalBackup: GatewayBackup = {
      timestamp: new Date().toISOString(),
      routedProviders: {},
    };
    // Mark skipped providers as routed (we don't know original URLs)
    for (const name of skipped) {
      minimalBackup.routedProviders[name] = {
        originalBaseUrl: GATEWAY_SERVER_URL, // Can't restore, but mark as managed
      };
    }
    writeFileSync(GATEWAY_BACKUP, JSON.stringify(minimalBackup, null, 2) + "\n", "utf-8");

    return {
      providers: skipped,
      warnings: ["Providers were already pointing to Nyx. Routing is now marked as enabled."],
    };
  }

  if (routedProviders.length === 0) {
    throw new Error("No providers found with baseUrl to route through Nyx");
  }

  // Write modified openclaw.json
  writeOpenClawConfig(config);

  // Also update agent models.json files
  const agentModelsBackup: Record<string, { files: string[]; originalBaseUrls: Record<string, string> }> = {};
  updateAgentModelsFiles(agentModelsBackup);
  if (Object.keys(agentModelsBackup).length > 0) {
    backup.agentModelsBackup = agentModelsBackup;
  }

  // Save backup
  mkdirSync(MOLTGUARD_DATA_DIR, { recursive: true });
  writeFileSync(GATEWAY_BACKUP, JSON.stringify(backup, null, 2) + "\n", "utf-8");

  const warnings: string[] = [];
  if (skipped.length > 0) {
    warnings.push(`Skipped providers already pointing to Nyx: ${skipped.join(", ")}`);
  }

  const modifiedAgentFiles = Object.keys(agentModelsBackup).length;
  if (modifiedAgentFiles > 0) {
    warnings.push(`Also updated ${modifiedAgentFiles} agent models.json file(s)`);
  }

  return { providers: routedProviders, warnings };
}

/**
 * Disable Nyx routing.
 * Restores original provider URLs in openclaw.json (智能恢复)
 */
export function disableGateway(): { providers: string[]; warnings: string[] } {
  if (!existsSync(GATEWAY_BACKUP)) {
    throw new Error("Nyx routing not enabled (no backup found)");
  }

  // Read backup
  const backup: GatewayBackup = loadJsonSync(GATEWAY_BACKUP);

  // Read current openclaw.json
  const config = readOpenClawConfig();
  if (!config.models?.providers) {
    throw new Error("No providers found in openclaw.json");
  }

  const providers = config.models.providers;
  const restoredProviders: string[] = [];
  const deletedProviders: string[] = [];
  const modifiedProviders: string[] = [];

  // Smart restore: 只恢复 baseUrl，保留其他字段的修改
  for (const [name, routeInfo] of Object.entries(backup.routedProviders)) {
    const provider = providers[name];

    if (!provider) {
      // Provider 被删除了
      deletedProviders.push(name);
      continue;
    }

    if (provider.baseUrl && isGatewayUrl(provider.baseUrl)) {
      // Provider still points to Nyx; restore original URL.
      provider.baseUrl = routeInfo.originalBaseUrl;
      restoredProviders.push(name);
    } else if (provider.baseUrl !== routeInfo.originalBaseUrl) {
      // Provider baseUrl was changed by user; keep custom value.
      modifiedProviders.push(name);
      // 不恢复，保留用户的修改
    } else {
      // Provider 的 baseUrl 已经是原始值了，无需恢复
    }
  }

  // Write restored config
  writeOpenClawConfig(config);

  // Restore agent models.json files
  let restoredAgentFiles = 0;
  if (backup.agentModelsBackup) {
    const restored = restoreAgentModelsFiles(backup.agentModelsBackup);
    restoredAgentFiles = restored.length;
  }

  // Delete backup
  unlinkSync(GATEWAY_BACKUP);

  const warnings: string[] = [];
  if (deletedProviders.length > 0) {
    warnings.push(`These providers were deleted and not restored: ${deletedProviders.join(", ")}`);
  }
  if (modifiedProviders.length > 0) {
    warnings.push(`These providers have custom baseUrl (kept as-is): ${modifiedProviders.join(", ")}`);
  }
  if (restoredAgentFiles > 0) {
    warnings.push(`Also restored ${restoredAgentFiles} agent models.json file(s)`);
  }

  return { providers: restoredProviders, warnings };
}

/**
 * Get Nyx routing status.
 */
export function getGatewayStatus(): GatewayStatus {
  const enabled = existsSync(GATEWAY_BACKUP);
  const running = isGatewayRunning();

  const status: GatewayStatus = {
    enabled,
    running,
    port: DEFAULT_GATEWAY_PORT,
    url: GATEWAY_SERVER_URL,
    providers: [],
  };

  if (enabled && existsSync(GATEWAY_BACKUP)) {
    const backup: GatewayBackup = loadJsonSync(GATEWAY_BACKUP);
    status.providers = Object.keys(backup.routedProviders);
  }

  return status;
}
