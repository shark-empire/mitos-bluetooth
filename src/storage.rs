use crate::bonding::Bond;
use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub name: String,
    pub discoverable: bool,
    pub auto_pin: bool,
    pub default_pin: String,
    pub trusted_only_connect: bool,
    pub auto_reconnect: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config { name: "mitos".into(), discoverable: false, auto_pin: true, default_pin: "0000".into(),
                 trusted_only_connect: false, auto_reconnect: true }
    }
}

/// Persistent state: bonds + configuration. All writes are atomic (tmp + rename).
pub struct Storage { dir: PathBuf }

impl Storage {
    pub fn new(dir: &str) -> Result<Self> {
        let d = PathBuf::from(dir);
        std::fs::create_dir_all(&d)?;
        Ok(Storage { dir: d })
    }
    pub fn load_config(&self) -> Config {
        std::fs::read_to_string(self.dir.join("config.json")).ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }
    pub fn save_config(&self, cfg: &Config) {
        let _ = self.write_atomic("config.json", serde_json::to_string_pretty(cfg).unwrap_or_default());
    }
    pub fn load_bonds(&self) -> Vec<Bond> {
        std::fs::read_to_string(self.dir.join("bonds.json")).ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }
    pub fn save_bonds(&self, bonds: &[Bond]) {
        let _ = self.write_atomic("bonds.json", serde_json::to_string_pretty(bonds).unwrap_or_default());
    }
    fn write_atomic(&self, name: &str, contents: String) -> Result<()> {
        let tmp = self.dir.join(format!("{name}.tmp"));
        let final_path = self.dir.join(name);
        std::fs::write(&tmp, contents.as_bytes())?;
        std::fs::rename(&tmp, &final_path)?;
        Ok(())
    }
}