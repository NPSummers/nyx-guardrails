use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_bind")]
    pub bind: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_sensitivity")]
    pub sensitivity: Sensitivity,
    #[serde(default)]
    pub rules: Rules,
    #[serde(default)]
    #[allow(dead_code)]
    pub code_block_passthrough: bool,
    #[serde(default)]
    #[allow(dead_code)]
    pub allowlist: Vec<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub blocklist: Vec<String>,
    #[serde(default)]
    pub bypass: Vec<String>,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub update_check: UpdateCheckConfig,
    #[serde(default)]
    #[allow(dead_code)]
    pub anti_prompt_injection: AntiPromptInjectionConfig,
    #[serde(default)]
    #[allow(dead_code)]
    pub project_monitoring: ProjectMonitoringConfig,
    #[serde(default)]
    #[allow(dead_code)]
    pub anti_exfiltration: AntiExfiltrationConfig,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Sensitivity {
    Low,
    Medium,
    High,
    Paranoid,
}

impl Default for Sensitivity {
    fn default() -> Self {
        Sensitivity::Medium
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rules {
    #[serde(default = "default_always_redact")]
    pub always_redact: Vec<String>,
    #[serde(default = "default_mask")]
    pub mask: Vec<String>,
    #[serde(default = "default_warn_only")]
    pub warn_only: Vec<String>,
}

impl Default for Rules {
    fn default() -> Self {
        Rules {
            always_redact: default_always_redact(),
            mask: default_mask(),
            warn_only: default_warn_only(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuditConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_audit_path")]
    pub path: PathBuf,
    #[serde(default)]
    pub log_values: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateCheckConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_update_timeout_ms")]
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct AntiPromptInjectionConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub fail_closed: bool,
    #[serde(default)]
    pub model: PromptInjectionModelConfig,
    #[serde(default = "default_injection_threshold")]
    pub threshold: f32,
    #[serde(default = "default_claude_md_threshold")]
    pub claude_md_threshold: f32,
    #[serde(default)]
    pub scan_mode: PromptInjectionScanMode,
    #[serde(default)]
    pub translation: TranslationConfig,
    #[serde(default)]
    pub fallback_heuristic: FallbackHeuristicConfig,
    #[serde(default)]
    pub detect: InjectionDetectConfig,
    #[serde(default)]
    pub chunking: ChunkingConfig,
    #[serde(default)]
    pub behavior: InjectionBehaviorConfig,
    #[serde(default)]
    pub custom_models: CustomModelsConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct PromptInjectionModelConfig {
    #[serde(default = "default_injection_model_repo")]
    pub repository: String,
    #[serde(default = "default_injection_label")]
    pub label_injection: String,
    #[serde(default = "default_safe_label")]
    pub label_safe: String,
    #[serde(default = "default_true")]
    pub requires_hf_auth: bool,
    #[serde(default = "default_hf_token_env")]
    pub hf_token_env: String,
    #[serde(default = "default_hf_token_path_env")]
    pub hf_token_path_env: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PromptInjectionScanMode {
    Fast,
    Full,
    Custom,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct TranslationConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub only_if_non_english: bool,
    #[serde(default = "default_source_lang")]
    pub source_language: String,
    #[serde(default = "default_target_lang")]
    pub target_language: String,
    #[serde(default = "default_translation_provider")]
    pub provider: String,
    #[serde(default = "default_translation_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_true")]
    pub fail_open_keep_original: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct FallbackHeuristicConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_heuristic_base_score")]
    pub base_score: f32,
    #[serde(default = "default_heuristic_per_marker_bonus")]
    pub per_marker_bonus: f32,
    #[serde(default = "default_heuristic_max_score")]
    pub max_score: f32,
    #[serde(default = "default_heuristic_safe_score")]
    pub safe_score: f32,
    #[serde(default = "default_suspicious_markers")]
    pub suspicious_markers: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct InjectionDetectConfig {
    #[serde(default = "default_true")]
    pub unicode_tricks: bool,
    #[serde(default = "default_true")]
    pub known_injection_phrases: bool,
    #[serde(default = "default_true")]
    pub ml_classifier: bool,
    #[serde(default = "default_true")]
    pub secrets_in_content: bool,
    #[serde(default = "default_true")]
    pub bash_exfiltration: bool,
    #[serde(default = "default_true")]
    pub script_exfiltration: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct ChunkingConfig {
    #[serde(default = "default_chunk_max_chars")]
    pub max_chars: usize,
    #[serde(default = "default_chunk_overlap_chars")]
    pub overlap_chars: usize,
    #[serde(default = "default_chunk_strategy")]
    pub strategy: String,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct InjectionBehaviorConfig {
    #[serde(default = "default_true")]
    pub scan_input_content: bool,
    #[serde(default = "default_true")]
    pub scan_output_content: bool,
    #[serde(default = "default_true")]
    pub auto_taint_on_detection: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct CustomModelsConfig {
    #[serde(default = "default_custom_models_path")]
    pub path: String,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct ProjectMonitoringConfig {
    #[serde(default)]
    pub ask_on_new_project: bool,
    #[serde(default)]
    pub ignore_dirs: Vec<String>,
    #[serde(default = "default_runtime_dir")]
    pub runtime_dir: String,
    #[serde(default = "default_repo_state_db")]
    pub repo_state_db: String,
    #[serde(default)]
    pub scan_cache: ScanCacheConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct ScanCacheConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_scan_cache_path")]
    pub path: String,
    #[serde(default = "default_scan_cache_ttl_days")]
    pub ttl_days: u64,
    #[serde(default = "default_scan_cache_prune_minutes")]
    pub prune_interval_minutes: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct AntiExfiltrationConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub detect_dns_tunneling: bool,
    #[serde(default = "default_obfuscation_markers")]
    pub detect_obfuscation: Vec<String>,
    #[serde(default)]
    pub sensitive_path_overrides: Vec<String>,
    #[serde(default)]
    pub blocked_domain_overrides: Vec<String>,
}

impl Default for UpdateCheckConfig {
    fn default() -> Self {
        UpdateCheckConfig {
            enabled: true,
            timeout_ms: default_update_timeout_ms(),
        }
    }
}

impl Default for AntiPromptInjectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            fail_closed: true,
            model: PromptInjectionModelConfig::default(),
            threshold: default_injection_threshold(),
            claude_md_threshold: default_claude_md_threshold(),
            scan_mode: PromptInjectionScanMode::default(),
            translation: TranslationConfig::default(),
            fallback_heuristic: FallbackHeuristicConfig::default(),
            detect: InjectionDetectConfig::default(),
            chunking: ChunkingConfig::default(),
            behavior: InjectionBehaviorConfig::default(),
            custom_models: CustomModelsConfig::default(),
        }
    }
}

impl Default for PromptInjectionModelConfig {
    fn default() -> Self {
        Self {
            repository: default_injection_model_repo(),
            label_injection: default_injection_label(),
            label_safe: default_safe_label(),
            requires_hf_auth: true,
            hf_token_env: default_hf_token_env(),
            hf_token_path_env: default_hf_token_path_env(),
        }
    }
}

impl Default for PromptInjectionScanMode {
    fn default() -> Self {
        Self::Fast
    }
}

impl Default for TranslationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            only_if_non_english: true,
            source_language: default_source_lang(),
            target_language: default_target_lang(),
            provider: default_translation_provider(),
            timeout_ms: default_translation_timeout_ms(),
            fail_open_keep_original: true,
        }
    }
}

impl Default for FallbackHeuristicConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            base_score: default_heuristic_base_score(),
            per_marker_bonus: default_heuristic_per_marker_bonus(),
            max_score: default_heuristic_max_score(),
            safe_score: default_heuristic_safe_score(),
            suspicious_markers: default_suspicious_markers(),
        }
    }
}

impl Default for InjectionDetectConfig {
    fn default() -> Self {
        Self {
            unicode_tricks: true,
            known_injection_phrases: true,
            ml_classifier: true,
            secrets_in_content: true,
            bash_exfiltration: true,
            script_exfiltration: true,
        }
    }
}

impl Default for ChunkingConfig {
    fn default() -> Self {
        Self {
            max_chars: default_chunk_max_chars(),
            overlap_chars: default_chunk_overlap_chars(),
            strategy: default_chunk_strategy(),
        }
    }
}

impl Default for InjectionBehaviorConfig {
    fn default() -> Self {
        Self {
            scan_input_content: true,
            scan_output_content: true,
            auto_taint_on_detection: true,
        }
    }
}

impl Default for CustomModelsConfig {
    fn default() -> Self {
        Self {
            path: default_custom_models_path(),
        }
    }
}

impl Default for ProjectMonitoringConfig {
    fn default() -> Self {
        Self {
            ask_on_new_project: false,
            ignore_dirs: vec![],
            runtime_dir: default_runtime_dir(),
            repo_state_db: default_repo_state_db(),
            scan_cache: ScanCacheConfig::default(),
        }
    }
}

impl Default for ScanCacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: default_scan_cache_path(),
            ttl_days: default_scan_cache_ttl_days(),
            prune_interval_minutes: default_scan_cache_prune_minutes(),
        }
    }
}

impl Default for AntiExfiltrationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            detect_dns_tunneling: true,
            detect_obfuscation: default_obfuscation_markers(),
            sensitive_path_overrides: vec![],
            blocked_domain_overrides: vec![],
        }
    }
}

impl Default for AuditConfig {
    fn default() -> Self {
        AuditConfig {
            enabled: true,
            path: default_audit_path(),
            log_values: false,
        }
    }
}

fn default_bind() -> String {
    "127.0.0.1".to_string()
}
fn default_port() -> u16 {
    8686
}
fn default_sensitivity() -> Sensitivity {
    Sensitivity::Medium
}
fn default_true() -> bool {
    true
}
fn default_update_timeout_ms() -> u64 {
    1200
}
fn default_injection_threshold() -> f32 {
    0.70
}
fn default_claude_md_threshold() -> f32 {
    0.90
}
fn default_injection_model_repo() -> String {
    "rogue-security/prompt-injection-jailbreak-sentinel-v2".to_string()
}
fn default_injection_label() -> String {
    "prompt_injection".to_string()
}
fn default_safe_label() -> String {
    "safe".to_string()
}
fn default_hf_token_env() -> String {
    "HF_TOKEN".to_string()
}
fn default_hf_token_path_env() -> String {
    "HF_TOKEN_PATH".to_string()
}
fn default_source_lang() -> String {
    "auto".to_string()
}
fn default_target_lang() -> String {
    "en".to_string()
}
fn default_translation_provider() -> String {
    "google_translate_unofficial".to_string()
}
fn default_translation_timeout_ms() -> u64 {
    8000
}
fn default_heuristic_base_score() -> f32 {
    0.55
}
fn default_heuristic_per_marker_bonus() -> f32 {
    0.10
}
fn default_heuristic_max_score() -> f32 {
    0.99
}
fn default_heuristic_safe_score() -> f32 {
    0.92
}
fn default_suspicious_markers() -> Vec<String> {
    vec![
        "ignore all previous instructions".into(),
        "ignore previous instructions".into(),
        "disregard any prior constraints".into(),
        "forget all safety rules".into(),
        "developer mode".into(),
        "system prompt".into(),
        "/etc/passwd".into(),
        "jailbreak".into(),
        "override".into(),
    ]
}
fn default_chunk_max_chars() -> usize {
    256
}
fn default_chunk_overlap_chars() -> usize {
    25
}
fn default_chunk_strategy() -> String {
    "head_tail".to_string()
}
fn default_custom_models_path() -> String {
    "~/.config/nyx-guardrails/models.toml".to_string()
}
fn default_runtime_dir() -> String {
    "~/.nyx-guardrails".to_string()
}
fn default_repo_state_db() -> String {
    "repo-state.redb".to_string()
}
fn default_scan_cache_path() -> String {
    "~/.nyx-guardrails/scan-cache.redb".to_string()
}
fn default_scan_cache_ttl_days() -> u64 {
    30
}
fn default_scan_cache_prune_minutes() -> u64 {
    60
}
fn default_obfuscation_markers() -> Vec<String> {
    vec!["base64".into(), "hex".into(), "rot13".into()]
}
fn default_audit_path() -> PathBuf {
    PathBuf::from("./nyx-guardrails-audit.jsonl")
}

fn default_always_redact() -> Vec<String> {
    vec![
        "SSN".into(),
        "CREDIT_CARD".into(),
        "PRIVATE_KEY".into(),
        "AWS_KEY".into(),
        "GITHUB_TOKEN".into(),
        "API_KEY".into(),
        "BEARER_TOKEN".into(),
        "CONNECTION_STRING".into(),
        "SECRET".into(),
    ]
}

fn default_mask() -> Vec<String> {
    vec!["EMAIL".into(), "PHONE".into()]
}

fn default_warn_only() -> Vec<String> {
    vec!["IP_ADDRESS".into()]
}

impl Config {
    pub fn load(path: Option<&str>) -> Self {
        let candidates = match path {
            Some(p) => vec![PathBuf::from(p)],
            None => vec![
                PathBuf::from("nyx-guardrails.yaml"),
                PathBuf::from("nyx-guardrails.yml"),
                dirs_next::home_dir()
                    .map(|h| h.join(".config").join("nyx-guardrails").join("nyx-guardrails.yaml"))
                    .unwrap_or_default(),
            ],
        };

        for candidate in &candidates {
            if candidate.exists() {
                if let Ok(contents) = std::fs::read_to_string(candidate) {
                    match serde_yaml::from_str(&contents) {
                        Ok(config) => {
                            tracing::info!("Loaded config from {}", candidate.display());
                            return config;
                        }
                        Err(e) => {
                            tracing::warn!("Failed to parse {}: {}", candidate.display(), e);
                        }
                    }
                }
            }
        }

        tracing::info!("No config file found, using defaults");
        Config {
            bind: default_bind(),
            port: default_port(),
            sensitivity: default_sensitivity(),
            rules: Rules::default(),
            code_block_passthrough: false,
            allowlist: vec![],
            blocklist: vec![],
            bypass: vec![],
            audit: AuditConfig::default(),
            dry_run: false,
            update_check: UpdateCheckConfig::default(),
            anti_prompt_injection: AntiPromptInjectionConfig::default(),
            project_monitoring: ProjectMonitoringConfig::default(),
            anti_exfiltration: AntiExfiltrationConfig::default(),
        }
    }

    /// Check if a host/URL should bypass filtering (pass through unmodified)
    pub fn is_bypassed(&self, upstream: &str) -> bool {
        if self.bypass.is_empty() {
            return false;
        }
        self.bypass.iter().any(|pattern| {
            // Match against the upstream URL or just the hostname
            upstream.contains(pattern)
        })
    }

    /// Check if a PII kind should be redacted given current sensitivity
    pub fn should_redact(&self, kind_label: &str) -> RedactAction {
        // Blocklist always wins
        // (blocklist matching is done on values, not kinds — handled elsewhere)

        if self.rules.always_redact.iter().any(|k| k == kind_label) {
            return RedactAction::Redact;
        }

        if self.rules.mask.iter().any(|k| k == kind_label) {
            return match self.sensitivity {
                Sensitivity::Low => RedactAction::Ignore,
                _ => RedactAction::Mask,
            };
        }

        if self.rules.warn_only.iter().any(|k| k == kind_label) {
            return match self.sensitivity {
                Sensitivity::High | Sensitivity::Paranoid => RedactAction::Redact,
                _ => RedactAction::Warn,
            };
        }

        match self.sensitivity {
            Sensitivity::Paranoid => RedactAction::Redact,
            _ => RedactAction::Ignore,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum RedactAction {
    Redact, // Replace with token [EMAIL_1_abc123]
    Mask,   // Replace with plausible fake
    Warn,   // Log but don't touch
    Ignore, // Do nothing
}

#[cfg(test)]
mod tests {
    use super::{Config, RedactAction};

    #[test]
    fn defaults_redact_connection_strings_and_secrets() {
        let cfg = Config::load(Some("this-file-does-not-exist.yaml"));
        assert_eq!(cfg.should_redact("CONNECTION_STRING"), RedactAction::Redact);
        assert_eq!(cfg.should_redact("SECRET"), RedactAction::Redact);
    }
}
