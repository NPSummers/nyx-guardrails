use reqwest::Client;
use serde_json::Value;
use std::time::Duration;

use crate::config::AntiPromptInjectionConfig;

#[derive(Debug, Clone)]
pub struct InjectionScanResult {
    pub detected: bool,
    pub score: f32,
    pub label: String,
    pub reason: String,
    pub translated: bool,
    pub language: String,
    pub used_fallback: bool,
}

#[derive(Debug)]
struct Prediction {
    label: String,
    score: f32,
}

pub async fn scan_prompt_injection(
    client: &Client,
    cfg: &AntiPromptInjectionConfig,
    text: &str,
) -> InjectionScanResult {
    let raw = text.trim();
    if !cfg.enabled || raw.is_empty() {
        return InjectionScanResult {
            detected: false,
            score: 0.0,
            label: "safe".to_string(),
            reason: "scanner disabled or empty input".to_string(),
            translated: false,
            language: "en".to_string(),
            used_fallback: false,
        };
    }

    let mut scan_text = raw.to_string();
    let mut detected_lang = "en".to_string();
    let mut translated = false;

    if cfg.translation.enabled {
        if let Some((out, lang, did_translate)) = translate_to_english(client, cfg, raw).await {
            scan_text = out;
            detected_lang = lang;
            translated = did_translate;
        }
    }

    match classify_with_model(client, cfg, &scan_text).await {
        Ok(pred) => {
            let detected = pred.score >= cfg.threshold;
            InjectionScanResult {
                detected,
                score: pred.score,
                label: pred.label,
                reason: "hf model inference".to_string(),
                translated,
                language: detected_lang,
                used_fallback: false,
            }
        }
        Err(model_err) => {
            if cfg.fallback_heuristic.enabled {
                let pred = classify_with_heuristic(cfg, &scan_text);
                let injection_score = to_injection_score(cfg, &pred.label, pred.score);
                let detected = injection_score >= cfg.threshold;
                InjectionScanResult {
                    detected,
                    score: injection_score,
                    label: pred.label,
                    reason: format!("heuristic fallback ({})", model_err),
                    translated,
                    language: detected_lang,
                    used_fallback: true,
                }
            } else if cfg.fail_closed {
                InjectionScanResult {
                    detected: true,
                    score: 1.0,
                    label: "prompt_injection".to_string(),
                    reason: format!("fail_closed: {}", model_err),
                    translated,
                    language: detected_lang,
                    used_fallback: true,
                }
            } else {
                InjectionScanResult {
                    detected: false,
                    score: 0.0,
                    label: "safe".to_string(),
                    reason: format!("model unavailable, fail_open: {}", model_err),
                    translated,
                    language: detected_lang,
                    used_fallback: true,
                }
            }
        }
    }
}

async fn translate_to_english(
    client: &Client,
    cfg: &AntiPromptInjectionConfig,
    text: &str,
) -> Option<(String, String, bool)> {
    // Avoid extremely large URL query payloads.
    if text.len() > 2000 {
        return Some((text.to_string(), "unknown".to_string(), false));
    }

    let req = client
        .get("https://translate.googleapis.com/translate_a/single")
        .query(&[
            ("client", "gtx"),
            ("sl", cfg.translation.source_language.as_str()),
            ("tl", cfg.translation.target_language.as_str()),
            ("dt", "t"),
            ("q", text),
        ])
        .timeout(Duration::from_millis(cfg.translation.timeout_ms));

    let resp = req.send().await.ok()?;
    let payload = resp.json::<Value>().await.ok()?;

    let detected_lang = payload
        .get(2)
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let translated = payload
        .get(0)
        .and_then(|v| v.as_array())
        .map(|parts| {
            parts
                .iter()
                .filter_map(|p| p.get(0).and_then(|x| x.as_str()))
                .collect::<String>()
                .trim()
                .to_string()
        })
        .unwrap_or_default();

    if cfg.translation.only_if_non_english && detected_lang.eq_ignore_ascii_case("en") {
        return Some((text.to_string(), detected_lang, false));
    }

    if !translated.is_empty() {
        return Some((translated, detected_lang, true));
    }

    if cfg.translation.fail_open_keep_original {
        return Some((text.to_string(), detected_lang, false));
    }

    None
}

async fn classify_with_model(
    client: &Client,
    cfg: &AntiPromptInjectionConfig,
    text: &str,
) -> Result<Prediction, String> {
    let token = resolve_hf_token(cfg)?;
    let model_url = format!(
        "https://router.huggingface.co/hf-inference/models/{}",
        cfg.model.repository
    );

    let request = client
        .post(model_url)
        .bearer_auth(token)
        .json(&serde_json::json!({
            "inputs": text,
            "options": { "wait_for_model": true }
        }))
        .timeout(Duration::from_secs(20));

    let resp = request
        .send()
        .await
        .map_err(|e| format!("hf request failed: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("hf status {}: {}", status, body));
    }

    let json = resp
        .json::<Value>()
        .await
        .map_err(|e| format!("hf json parse failed: {}", e))?;

    let preds = parse_predictions(&json)?;
    let mut best = Prediction {
        label: cfg.model.label_safe.clone(),
        score: 0.0,
    };

    for p in preds {
        let score = to_injection_score(cfg, &p.label, p.score);
        if score > best.score {
            best = Prediction {
                label: p.label,
                score,
            };
        }
    }

    Ok(best)
}

fn resolve_hf_token(cfg: &AntiPromptInjectionConfig) -> Result<String, String> {
    if let Ok(tok) = std::env::var(&cfg.model.hf_token_env) {
        let trimmed = tok.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }

    if let Ok(path) = std::env::var(&cfg.model.hf_token_path_env) {
        let p = path.trim();
        if !p.is_empty() {
            let content = std::fs::read_to_string(p)
                .map_err(|e| format!("failed to read token file {}: {}", p, e))?;
            let trimmed = content.trim().to_string();
            if !trimmed.is_empty() {
                return Ok(trimmed);
            }
        }
    }

    if cfg.model.requires_hf_auth {
        return Err(format!(
            "missing HF auth token (set {} or {})",
            cfg.model.hf_token_env, cfg.model.hf_token_path_env
        ));
    }

    Ok(String::new())
}

fn parse_predictions(json: &Value) -> Result<Vec<Prediction>, String> {
    let arr = if let Some(a) = json.as_array() {
        a
    } else {
        return Err("hf output not an array".to_string());
    };

    let mut out = Vec::new();

    if let Some(first) = arr.first() {
        if let Some(nested) = first.as_array() {
            for item in nested {
                if let Some(pred) = parse_prediction_item(item) {
                    out.push(pred);
                }
            }
        } else {
            for item in arr {
                if let Some(pred) = parse_prediction_item(item) {
                    out.push(pred);
                }
            }
        }
    }

    if out.is_empty() {
        return Err("hf output contains no predictions".to_string());
    }

    Ok(out)
}

fn parse_prediction_item(v: &Value) -> Option<Prediction> {
    Some(Prediction {
        label: v.get("label")?.as_str()?.to_string(),
        score: v.get("score")?.as_f64()? as f32,
    })
}

fn to_injection_score(cfg: &AntiPromptInjectionConfig, label: &str, score: f32) -> f32 {
    if label.eq_ignore_ascii_case(&cfg.model.label_injection) {
        return score;
    }
    if label.eq_ignore_ascii_case(&cfg.model.label_safe) {
        return 1.0 - score;
    }

    let lower = label.to_ascii_lowercase();
    if lower.contains("inject") || lower.contains("jailbreak") || lower.contains("malicious") {
        return score;
    }

    0.0
}

fn classify_with_heuristic(cfg: &AntiPromptInjectionConfig, text: &str) -> Prediction {
    let lowered = text.to_ascii_lowercase();
    let marker_hits = cfg
        .fallback_heuristic
        .suspicious_markers
        .iter()
        .filter(|m| lowered.contains(&m.to_ascii_lowercase()))
        .count() as f32;

    if marker_hits == 0.0 {
        return Prediction {
            label: cfg.model.label_safe.clone(),
            score: cfg.fallback_heuristic.safe_score,
        };
    }

    let mut score = cfg.fallback_heuristic.base_score
        + (cfg.fallback_heuristic.per_marker_bonus * marker_hits);
    if score > cfg.fallback_heuristic.max_score {
        score = cfg.fallback_heuristic.max_score;
    }

    Prediction {
        label: cfg.model.label_injection.clone(),
        score,
    }
}
