use crate::bonding::Bond;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
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
        Config {
            name: "mitos".into(),
            discoverable: false,
            auto_pin: true,
            default_pin: "0000".into(),
            trusted_only_connect: false,
            auto_reconnect: true,
        }
    }
}

/// Persistent state: bonds (link keys!) + configuration.
/// The directory is created 0700 and every file 0600; writes are atomic and durable
/// (temp file + fsync + rename + directory fsync), so a power cut never leaves a torn file.
pub struct Storage {
    dir: PathBuf,
}

impl Storage {
    pub fn new(dir: &str) -> Result<Self> {
        let d = PathBuf::from(dir);
        let fresh = !d.exists();
        std::fs::create_dir_all(&d)?;
        if fresh {
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(Storage { dir: d })
    }

    /// Parse `name`; a corrupt file is preserved as `<name>.corrupt` instead of being silently overwritten.
    fn read_json<T: serde::de::DeserializeOwned>(&self, name: &str) -> Option<T> {
        let path = self.dir.join(name);
        let text = std::fs::read_to_string(&path).ok()?;
        match serde_json::from_str(&text) {
            Ok(v) => Some(v),
            Err(e) => {
                eprintln!("[storage] {name} is corrupt ({e}); keeping it as {name}.corrupt");
                let _ = std::fs::rename(&path, self.dir.join(format!("{name}.corrupt")));
                None
            }
        }
    }

    pub fn load_config(&self) -> Config {
        self.read_json("config.json").unwrap_or_default()
    }

    pub fn save_config(&self, cfg: &Config) {
        self.save("config.json", cfg);
    }

    pub fn load_bonds(&self) -> Vec<Bond> {
        self.read_json("bonds.json").unwrap_or_default()
    }

    pub fn save_bonds(&self, bonds: &[Bond]) {
        self.save("bonds.json", bonds);
    }

    fn save<T: Serialize + ?Sized>(&self, name: &str, value: &T) {
        let result =
            serde_json::to_string_pretty(value).map_err(Error::from).and_then(|text| self.write_atomic(name, &text));
        if let Err(e) = result {
            eprintln!("[storage] could not save {name}: {e}");
        }
    }

    fn write_atomic(&self, name: &str, contents: &str) -> Result<()> {
        let tmp = self.dir.join(format!("{name}.tmp"));
        let dest = self.dir.join(name);
        {
            let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
            f.write_all(contents.as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &dest)?;
        if let Ok(d) = std::fs::File::open(&self.dir) {
            let _ = d.sync_all();
        }
        Ok(())
    }
}
