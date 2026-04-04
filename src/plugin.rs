use crate::redactor::detect;
use chrono::Utc;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct DashboardEvent {
    pub ts: String,
    pub level: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct FileWarning {
    pub path: String,
    pub reason: String,
}

#[derive(Debug)]
pub struct PluginState {
    pub sanitize_enabled: bool,
    pub dashboard_token: String,
    pub root_dir: PathBuf,
    pub last_scan_at: Option<String>,
    pub warnings: Vec<FileWarning>,
    pub events: VecDeque<DashboardEvent>,
}

impl PluginState {
    pub fn new(root_dir: PathBuf) -> Self {
        let token = uuid::Uuid::new_v4().simple().to_string();
        Self {
            sanitize_enabled: true,
            dashboard_token: token,
            root_dir,
            last_scan_at: None,
            warnings: Vec::new(),
            events: VecDeque::new(),
        }
    }

    pub fn push_event(&mut self, level: &str, message: impl Into<String>) {
        self.events.push_back(DashboardEvent {
            ts: Utc::now().to_rfc3339(),
            level: level.to_string(),
            message: message.into(),
        });
        while self.events.len() > 200 {
            let _ = self.events.pop_front();
        }
    }

    pub fn handle_ngr_sanitize(&mut self, arg: &str) -> String {
        match arg {
            "on" => {
                self.sanitize_enabled = true;
                self.push_event("info", "sanitize mode enabled");
                "ngr_sanitize: ON\nOpenClaw base URL should point to this proxy (example: http://127.0.0.1:8686/openai).".to_string()
            }
            "off" => {
                self.sanitize_enabled = false;
                self.push_event("warn", "sanitize mode disabled");
                "ngr_sanitize: OFF\nOriginal API paths are restored (pass-through behavior).".to_string()
            }
            "none" => {
                format!(
                    "ngr_sanitize status: {}\nDashboard events: {}\nLast file scan warnings: {}",
                    if self.sanitize_enabled { "ON" } else { "OFF" },
                    self.events.len(),
                    self.warnings.len()
                )
            }
            _ => "usage: /ngr_sanitize <on|off|none>".to_string(),
        }
    }

    pub fn dashboard_command_output(&self, port: u16) -> String {
        format!(
            "NGR dashboard token: {}\nOpen URL: http://127.0.0.1:{}/ngr/dashboard?token={}",
            self.dashboard_token, port, self.dashboard_token
        )
    }

    pub fn run_file_scan(&mut self) {
        let mut warnings = Vec::new();
        scan_dir(&self.root_dir, &mut warnings);
        self.warnings = warnings;
        self.last_scan_at = Some(Utc::now().to_rfc3339());
        self.push_event(
            "info",
            format!("file scan completed with {} warnings", self.warnings.len()),
        );
    }

    pub fn render_dashboard_html(&self) -> String {
        let sanitize = if self.sanitize_enabled { "ON" } else { "OFF" };
        let scanned_at = self
            .last_scan_at
            .clone()
            .unwrap_or_else(|| "never".to_string());

        let mut events_html = String::new();
        for e in self.events.iter().rev().take(80) {
            events_html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(&e.ts),
                html_escape(&e.level),
                html_escape(&e.message)
            ));
        }

        let mut warnings_html = String::new();
        for w in self.warnings.iter().take(400) {
            warnings_html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td></tr>",
                html_escape(&w.path),
                html_escape(&w.reason)
            ));
        }

        format!(
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>NGR Dashboard</title>\
            <style>body{{font-family:Segoe UI,Arial,sans-serif;margin:18px;background:#0f1116;color:#e8ecf1}}\
            table{{border-collapse:collapse;width:100%;margin-bottom:18px}}td,th{{border:1px solid #2b3240;padding:6px 8px;text-align:left}}\
            th{{background:#1a2130}}.pill{{display:inline-block;padding:2px 8px;border-radius:12px;background:#22304a}}</style></head>\
            <body><h1>Nyx Guardrails Dashboard</h1>\
            <p><span class=\"pill\">sanitize: {}</span> <span class=\"pill\">warnings: {}</span></p>\
            <p>Last file scan: {}</p>\
            <h2>Recent Events</h2><table><tr><th>Time</th><th>Level</th><th>Message</th></tr>{}</table>\
            <h2>File Scan Warnings</h2><table><tr><th>Path</th><th>Reason</th></tr>{}</table>\
            </body></html>",
            sanitize,
            self.warnings.len(),
            html_escape(&scanned_at),
            events_html,
            warnings_html
        )
    }
}

fn scan_dir(root: &Path, out: &mut Vec<FileWarning>) {
    let ignored_dirs = [".git", "target", "node_modules", ".cursor", ".vscode"];
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                if ignored_dirs.iter().any(|i| i.eq_ignore_ascii_case(name)) {
                    continue;
                }
            }
            scan_dir(&path, out);
            continue;
        }

        if !looks_like_text_file(&path) {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        if content.len() > 2_000_000 {
            continue;
        }

        let pii = detect(&content);
        if !pii.is_empty() {
            out.push(FileWarning {
                path: path.display().to_string(),
                reason: format!("possible secret/PII matches: {}", pii.len()),
            });
        }

        let lower = content.to_ascii_lowercase();
        let injection_markers = [
            "ignore all previous instructions",
            "ignore previous instructions",
            "developer mode",
            "system prompt",
            "jailbreak",
            "override safety",
            "/etc/passwd",
        ];
        let hits = injection_markers.iter().filter(|m| lower.contains(**m)).count();
        if hits > 0 {
            out.push(FileWarning {
                path: path.display().to_string(),
                reason: format!("possible prompt-injection markers: {}", hits),
            });
        }
    }
}

fn looks_like_text_file(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let text_exts = [
        "rs", "md", "txt", "json", "yaml", "yml", "toml", "py", "js", "ts", "tsx", "jsx", "c",
        "cpp", "h", "hpp", "java", "go", "sh", "ps1", "env", "ini",
    ];
    text_exts.contains(&ext.as_str())
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
