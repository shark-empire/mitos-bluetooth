use crate::device::DeviceId;
use crate::profile::ProfileKind;
use crate::smp::LeKeys;
use crate::storage::Storage;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bond {
    pub device: DeviceId,
    pub name: Option<String>,
    pub class: u32,
    pub link_key: Option<[u8; 16]>,
    pub link_key_type: Option<u8>,
    pub le_ltk: Option<[u8; 16]>,
    pub le_ediv: u16,
    pub le_rand: u64,
    pub le_irk: Option<[u8; 16]>,
    pub trusted: bool,
    pub profiles: Vec<ProfileKind>,
    pub created: u64,
    pub last_connected: u64,
}

pub struct BondStore { store: Arc<Storage>, bonds: Mutex<HashMap<DeviceId, Bond>> }

impl BondStore {
    pub fn new(store: Arc<Storage>) -> Self {
        let bonds = store.load_bonds().into_iter().map(|b| (b.device, b)).collect();
        BondStore { store, bonds: Mutex::new(bonds) }
    }
    pub fn get(&self, id: &DeviceId) -> Option<Bond> { self.bonds.lock().unwrap().get(id).cloned() }
    pub fn list(&self) -> Vec<Bond> { let mut v: Vec<Bond> = self.bonds.lock().unwrap().values().cloned().collect(); v.sort_by_key(|b| b.device); v }
    pub fn is_bonded(&self, id: &DeviceId) -> bool { self.bonds.lock().unwrap().contains_key(id) }

    pub fn upsert_classic(&self, id: &DeviceId, key: &[u8; 16], key_type: u8, name: Option<String>) {
        let mut b = self.bonds.lock().unwrap();
        let entry = b.entry(*id).or_insert_with(|| Bond {
            device: *id, name, class: 0, link_key: None, link_key_type: None,
            le_ltk: None, le_ediv: 0, le_rand: 0, le_irk: None,
            trusted: true, profiles: Vec::new(), created: crate::device::now_ts(), last_connected: 0,
        });
        entry.link_key = Some(*key);
        entry.link_key_type = Some(key_type);
        if entry.name.is_none() { entry.name = name; }
        let snapshot: Vec<Bond> = b.values().cloned().collect();
        drop(b);
        self.store.save_bonds(&snapshot);
    }

    pub fn upsert_le(&self, id: &DeviceId, keys: &LeKeys, name: Option<String>) {
        let mut b = self.bonds.lock().unwrap();
        let entry = b.entry(*id).or_insert_with(|| Bond {
            device: *id, name, class: 0, link_key: None, link_key_type: None,
            le_ltk: None, le_ediv: 0, le_rand: 0, le_irk: None,
            trusted: true, profiles: Vec::new(), created: crate::device::now_ts(), last_connected: 0,
        });
        entry.le_ltk = Some(keys.ltk);
        entry.le_ediv = keys.ediv;
        entry.le_rand = keys.rand;
        entry.le_irk = keys.irk;
        if entry.name.is_none() { entry.name = name; }
        let snapshot: Vec<Bond> = b.values().cloned().collect();
        drop(b);
        self.store.save_bonds(&snapshot);
    }

    pub fn set_trusted(&self, id: &DeviceId, trusted: bool) -> bool {
        let mut b = self.bonds.lock().unwrap();
        if let Some(e) = b.get_mut(id) { e.trusted = trusted; let s: Vec<Bond> = b.values().cloned().collect(); drop(b); self.store.save_bonds(&s); true } else { false }
    }
    pub fn touch_connected(&self, id: &DeviceId) {
        let mut b = self.bonds.lock().unwrap();
        if let Some(e) = b.get_mut(id) { e.last_connected = crate::device::now_ts(); let s: Vec<Bond> = b.values().cloned().collect(); drop(b); self.store.save_bonds(&s); }
    }
    pub fn remove(&self, id: &DeviceId) -> bool {
        let mut b = self.bonds.lock().unwrap();
        let