use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub ignore: HashSet<String>,
    #[serde(default)]
    pub disable_rules: HashSet<String>,
    pub max_file_bytes: Option<u64>,
}

pub fn load_config(repo_root: &Path) -> Config {
    let config_path = repo_root.join(".gitprotect.toml");
    if !config_path.exists() {
        return Config::default();
    }

    match fs::read_to_string(&config_path) {
        Ok(content) => toml::from_str(&content).unwrap_or_default(),
        Err(_) => Config::default(),
    }
}

pub fn load_baseline(repo_root: &Path) -> HashSet<String> {
    let baseline_path = repo_root.join(".gitprotect-baseline.json");
    if !baseline_path.exists() {
        return HashSet::new();
    }

    match fs::read_to_string(&baseline_path) {
        Ok(content) => {
            let list: Vec<String> = serde_json::from_str(&content).unwrap_or_default();
            list.into_iter().collect()
        }
        Err(_) => HashSet::new(),
    }
}

pub fn save_baseline(repo_root: &Path, fingerprints: &[String]) -> std::io::Result<()> {
    let mut sorted: Vec<String> = fingerprints.to_vec();
    sorted.sort();
    sorted.dedup();

    let json =
        serde_json::to_string_pretty(&sorted).map_err(|e| std::io::Error::other(e.to_string()))?;

    let baseline_path = repo_root.join(".gitprotect-baseline.json");
    fs::write(baseline_path, json + "\n")
}
