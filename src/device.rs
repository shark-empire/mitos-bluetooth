use crate::error::{Error, Result};
use crate::profile::ProfileKind;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub type DeviceTable = Mutex<HashMap<DeviceId, Device>>;

pub fn now_ts() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
pub fn to_hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
pub fn from_hex(s: &str) -> Result<Vec<u8>> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if s.len() % 2 != 0 { return Err(Error::InvalidArgument("odd hex length".into())); }
    let mut v = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    for i in (0..b.len()).step_by(2) {
        let hi = (b[i] as char).to_digit(16).ok_or_else(|| Error::InvalidArgument("bad hex".into()))?;
        let lo = (b[i + 1] as char).to_digit(16).ok_or_else(|| Error::InvalidArgument("bad hex".into()))?;
        v.push(((hi << 4) | lo) as u8);
    }
    Ok(v)
}

/// BD_ADDR stored in over-the-air byte order (LSB first).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct Address(pub [u8; 6]);

impl Address {
    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 { return Err(Error::InvalidArgument(format!("bad address '{s}'"))); }
        let mut a = [0u8; 6];
        for i in 0..6 {
            a[5 - i] = u8::from_str_radix(parts[i], 16).map_err(|_| Error::InvalidArgument("bad address byte".into()))?;
        }
        Ok(Address(a))
    }
    pub fn nil() -> Self { Address([0; 6]) }
}
impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", self.0[5], self.0[4], self.0[3], self.0[2], self.0[1], self.0[0])
    }
}
impl std::str::FromStr for Address {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> { Address::parse(s) }
}
impl Serialize for Address {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> { s.serialize_str(&self.to_string()) }
}
impl<'de> Deserialize<'de> for Address {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Address::parse(&s).map_err(serde::de::Error::custom)
    }
}
use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AddressType { Bredr, LePublic, LeRandom }

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct DeviceId { pub address: Address, #[serde(rename = "type")] pub address_type: AddressType }

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.address_type { AddressType::Bredr => write!(f, "{}", self.address), _ => write!(f, "{}/le", self.address) }
    }
}

/// 24-bit Class of Device.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct DeviceClass(pub u32);

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DeviceKind { Unknown, Computer, Phone, AudioVideo, Keyboard, Pointing, KeyboardPointing, Peripheral, Imaging, Wearable, Toy, Health, Uncategorized }

impl DeviceClass {
    pub fn major(&self) -> u8 { ((self.0 >> 8) & 0x1f) as u8 }
    pub fn minor(&self) -> u8 { ((self.0 >> 2) & 0x3f) as u8 }
    pub fn services(&self) -> u16 { (self.0 >> 13) as u16 }
    pub fn is_keyboard(&self) -> bool { self.major() == 5 && (self.0 & 0xc0) == 0x40 }
    pub fn is_pointing(&self) -> bool { self.major() == 5 && (self.0 & 0xc0) == 0x80 }
    pub fn is_combo(&self) -> bool { self.major() == 5 && (self.0 & 0xc0) == 0xc0 }
    pub fn is_audio_video(&self) -> bool { self.major() == 4 }
    pub fn is_phone(&self) -> bool { self.major() == 2 }
    pub fn is_computer(&self) -> bool { self.major() == 1 }
    pub fn kind(&self) -> DeviceKind {
        match self.major() {
            1 => DeviceKind::Computer,
            2 => DeviceKind::Phone,
            4 => DeviceKind::AudioVideo,
            5 if self.is_keyboard() => DeviceKind::Keyboard,
            5 if self.is_pointing() => DeviceKind::Pointing,
            5 if self.is_combo() => DeviceKind::KeyboardPointing,
            5 => DeviceKind::Peripheral,
            6 => DeviceKind::Imaging,
            7 => DeviceKind::Wearable,
            8 => DeviceKind::Toy,
            9 => DeviceKind::Health,
            0x1f => DeviceKind::Uncategorized,
            _ => DeviceKind::Unknown,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DeviceState { Discovered, Pairing, Paired, Connecting, Connected, Disconnecting, Disconnected }

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceProperties {
    pub name: Option<String>,
    pub alias: Option<String>,
    pub rssi: Option<i8>,
    pub tx_power: Option<i8>,
    #[serde(rename = "class")] pub class: DeviceClass,
    pub uuids: Vec<u16>,
    pub uuids128: Vec<String>,
    pub appearance: Option<u16>,
    pub manufacturer: Option<(u16, Vec<u8>)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    pub id: DeviceId,
    pub properties: DeviceProperties,
    pub state: DeviceState,
    pub paired: bool,
    pub trusted: bool,
    pub connected: bool,
    pub profiles: Vec<ProfileKind>,
    pub last_seen: u64,
    pub last_connected: Option<u64>,
}

impl Device {
    pub fn new(id: DeviceId) -> Self {
        Device {
            id, state: DeviceState::Discovered, paired: false, trusted: false, connected: false,
            profiles: Vec::new(), last_seen: now_ts(), last_connected: None,
            properties: DeviceProperties { name: None, alias: None, rssi: None, tx_power: None,
                class: DeviceClass(0), uuids: Vec::new(), uuids128: Vec::new(), appearance: None, manufacturer: None },
        }
    }
    pub fn display_name(&self) -> String {
        self.properties.alias.clone().or_else(|| self.properties.name.clone()).unwrap_or_else(|| self.id.address.to_string())
    }
    /// Returns true if something user-visible changed (for DeviceFound/DeviceUpdated decisions).
    pub fn apply_ad(&mut self, ad: &EirData, rssi: i8) -> bool {
        let mut changed = false;
        self.last_seen = now_ts();
        if self.properties.rssi != Some(rssi) { self.properties.rssi = Some(rssi); changed = true; }
        if let Some(n) = &ad.name { if ad.complete_name && self.properties.name.as_deref() != Some(n.as_str()) { self.properties.name = Some(n.clone()); changed = true; } }
        else if let Some(n) = &ad.short_name { if self.properties.name.is_none() { self.properties.name = Some(n.clone()); changed = true; } }
        if ad.class_of_device != 0 && self.properties.class.0 != ad.class_of_device { self.properties.class = DeviceClass(ad.class_of_device); changed = true; }
        if !ad.uuids16.is_empty() { for u in &ad.uuids16 { if !self.properties.uuids.contains(u) { self.properties.uuids.push(*u); changed = true; } } }
        for u in &ad.uuids128 { if !self.properties.uuids128.contains(u) { self.properties.uuids128.push(u.clone()); changed = true; } }
        if let Some(t) = ad.tx_power { self.properties.tx_power = Some(t); }
        if let Some(a) = ad.appearance { self.properties.appearance = Some(a); }
        if ad.manufacturer.is_some() { self.properties.manufacturer = ad.manufacturer.clone(); }
        changed
    }
    pub fn guessed_profiles(&self) -> Vec<ProfileKind> {
        let mut v: Vec<ProfileKind> = self.properties.uuids.iter().filter_map(|u| crate::profile::uuid16_profile(*u)).collect();
        if v.is_empty() {
            if self.properties.class.is_keyboard() || self.properties.class.is_combo() { v.push(ProfileKind::Hid); }
            else if self.properties.class.is_audio_video() { v.push(ProfileKind::A2dp); v.push(ProfileKind::Avrcp); }
        }
        v.sort(); v.dedup();
        v
    }
}

#[derive(Default, Debug, Clone)]
pub struct EirData {
    pub name: Option<String>, pub short_name: Option<String>, pub complete_name: bool,
    pub uuids16: Vec<u16>, pub uuids128: Vec<String>, pub tx_power: Option<i8>,
    pub class_of_device: u32, pub manufacturer: Option<(u16, Vec<u8>)>, pub appearance: Option<u16>,
    pub flags: u8,
}

/// Parses EIR (BR/EDR) / Advertising Data (LE) — identical format.
pub fn parse_eir(data: &[u8]) -> EirData {
    let mut out = EirData::default();
    let mut i = 0;
    while i + 1 < data.len() {
        let len = data[i] as usize;
        if len == 0 || i + 1 + len > data.len() { break; }
        let t = data[i + 1];
        let d = &data[i + 2..i + 1 + len];
        match t {
            0x01 if !d.is_empty() => out.flags = d[0],
            0x02 | 0x03 | 0x04 | 0x05 => for c in d.chunks(2) { if c.len() == 2 { out.uuids16.push(u16::from_le_bytes([c[0], c[1]])); } },
            0x06 | 0x07 => for c in d.chunks(16) { if c.len() == 16 { out.uuids128.push(uuid128_str(c)); } },
            0x08 => out.short_name = Some(String::from_utf8_lossy(d).trim_end_matches('\0').to_string()),
            0x09 => { out.name = Some(String::from_utf8_lossy(d).trim_end_matches('\0').to_string()); out.complete_name = true; }
            0x0A if !d.is_empty() => out.tx_power = Some(d[0] as i8),
            0x0D if d.len() >= 3 => out.class_of_device = u32::from_le_bytes([d[0], d[1], d[2], 0]), // 3-byte CoD, zero-padded to 32 bits
            0x16 => {} // service data
            0x19 if d.len() >= 2 => out.appearance = Some(u16::from_le_bytes([d[0], d[1]])),
            0xFF if d.len() >= 2 => out.manufacturer = Some((u16::from_le_bytes([d[0], d[1]]), d[2..].to_vec())),
            _ => {}
        }
        i += 1 + len;
    }
    out
}

pub fn uuid128_str(b: &[u8]) -> String {
    // stored big-endian display form 0000xxxx-0000-1000-8000-00805f9b34fb
    let mut m = [0u8; 16];
    m.copy_from_slice(&b[..16]);
    m.reverse();
    format!("{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8], m[9], m[10], m[11], m[12], m[13], m[14], m[15])
}

/// Standard Bluetooth base UUID helper: 16-bit -> 128-bit string.
pub fn uuid16_to_128(u: u16) -> String {
    format!("{u:08x}-0000-1000-8000-00805f9b34fb")
}