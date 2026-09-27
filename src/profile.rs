use crate::audio::AudioManager;
use crate::device::DeviceId;
use crate::error::{Error, Result};
use crate::gatt::GattManager;
use crate::hid::HidHost;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProfileKind { Hid, A2dp, Avrcp, Hfp, Hsp, Gatt }

impl ProfileKind {
    pub fn label(&self) -> &'static str {
        match self { ProfileKind::Hid => "hid", ProfileKind::A2dp => "a2dp", ProfileKind::Avrcp => "avrcp",
                     ProfileKind::Hfp => "hfp", ProfileKind::Hsp => "hsp", ProfileKind::Gatt => "gatt" }
    }
    pub fn from_label(s: &str) -> Option<ProfileKind> {
        match s { "hid" => Some(ProfileKind::Hid), "a2dp" => Some(ProfileKind::A2dp), "avrcp" => Some(ProfileKind::Avrcp),
                  "hfp" => Some(ProfileKind::Hfp), "hsp" => Some(ProfileKind::Hsp), "gatt" => Some(ProfileKind::Gatt), _ => None }
    }
}
impl std::fmt::Display for ProfileKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{}", self.label()) }
}

/// Map advertised service UUIDs to profiles.
pub fn uuid16_profile(u: u16) -> Option<ProfileKind> {
    match u {
        0x1108 | 0x1112 => Some(ProfileKind::Hsp),                          // Headset / Headset-AG
        0x110a | 0x110b => Some(ProfileKind::A2dp),                          // A2DP source / sink
        0x110c | 0x110d | 0x110e | 0x110f => Some(ProfileKind::Avrcp),       // AVRCP
        0x111e | 0x111f => Some(ProfileKind::Hfp),                           // Handsfree
        0x1124 | 0x1812 => Some(ProfileKind::Hid),                           // HID / HID-over-GATT
        _ => None,
    }
}

/// Extension point: register custom profiles with `ProfileManager::register`.
pub trait Profile: Send + Sync {
    fn kind(&self) -> ProfileKind;
    fn connect(&self, device: &DeviceId, handle: u16, le: bool) -> Result<()>;
    fn disconnect(&self, device: &DeviceId) -> Result<()>;
}

pub struct ProfileManager {
    pub hid: Arc<HidHost>,
    pub gatt: Arc<GattManager>,
    pub audio: Arc<AudioManager>,
    custom: Mutex<Vec<Arc<dyn Profile>>>,
}

impl ProfileManager {
    pub fn new(hid: Arc<HidHost>, gatt: Arc<GattManager>, audio: Arc<AudioManager>) -> Self {
        ProfileManager { hid, gatt, audio, custom: Mutex::new(Vec::new()) }
    }
    pub fn register(&self, p: Arc<dyn Profile>) { self.custom.lock().unwrap().push(p); }

    pub fn connect(&self, device: &DeviceId, handle: u16, le: bool, kind: ProfileKind) -> Result<()> {
        for p in self.custom.lock().unwrap().iter() {
            if p.kind() == kind { return p.connect(device, handle, le); }
        }
        match kind {
            ProfileKind::Hid => self.hid.connect(device, handle, le),
            ProfileKind::Gatt => if le { Ok(()) } else { Err(Error::NotSupported("GATT over BR/EDR arrives with gatt.rs".into())) },
            ProfileKind::A2dp => self.audio.connect_a2dp(device, handle),
            ProfileKind::Avrcp => self.audio.connect_avrcp(device, handle),
            ProfileKind::Hfp => self.audio.connect_hfp(device, handle),
            ProfileKind::Hsp => self.audio.connect_hsp(device, handle),
        }
    }

    pub fn disconnect(&self, device: &DeviceId) -> Result<()> {
        let _ = self.hid.disconnect(device);
        let _ = self.audio.disconnect(device);
        for p in self.custom.lock().unwrap().iter() { let _ = p.disconnect(device); }
        Ok(())
    }
    /// Called by ConnectionManager when a SCO/eSCO connection request arrives.
    pub fn accept_sco(&self, addr: &crate::device::Address) -> bool { self.audio.accept_sync(addr) }
}