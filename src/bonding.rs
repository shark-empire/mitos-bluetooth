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

fn new_bond(id: &DeviceId) -> Bond {
    Bond {
        device: *id,
        name: None,
        class: 0,
        link_key: None,
        link_key_type: None,
        le_ltk: None,
        le_ediv: 0,
        le_rand: 0,
        le_irk: None,
        trusted: true,
        profiles: Vec::new(),
        created: crate::device::now_ts(),
        last_connected: 0,
    }
}

pub struct BondStore {
    store: Arc<Storage>,
    bonds: Mutex<HashMap<DeviceId, Bond>>,
    /// Serialises disk writes so a slow older snapshot can never overwrite a newer one.
    save_lock: Mutex<()>,
}

impl BondStore {
    pub fn new(store: Arc<Storage>) -> Self {
        let bonds = store.load_bonds().into_iter().map(|b| (b.device, b)).collect();
        BondStore { store, bonds: Mutex::new(bonds), save_lock: Mutex::new(()) }
    }

    /// Write the *current* state; callers mutate first, then call this.
    fn persist(&self) {
        let _one_writer = self.save_lock.lock().unwrap();
        let mut snapshot: Vec<Bond> = self.bonds.lock().unwrap().values().cloned().collect();
        snapshot.sort_by_key(|b| b.device);
        self.store.save_bonds(&snapshot);
    }

    pub fn get(&self, id: &DeviceId) -> Option<Bond> {
        self.bonds.lock().unwrap().get(id).cloned()
    }

    pub fn list(&self) -> Vec<Bond> {
        let mut v: Vec<Bond> = self.bonds.lock().unwrap().values().cloned().collect();
        v.sort_by_key(|b| b.device);
        v
    }

    pub fn is_bonded(&self, id: &DeviceId) -> bool {
        self.bonds.lock().unwrap().contains_key(id)
    }

    /// Bonded by any transport (a dual-mode device may hold both a BR/EDR and an LE bond).
    pub fn is_bonded_address(&self, address: &crate::device::Address) -> bool {
        self.bonds.lock().unwrap().keys().any(|k| k.address == *address)
    }

    pub fn upsert_classic(&self, id: &DeviceId, key: &[u8; 16], key_type: u8, name: Option<String>) {
        {
            let mut b = self.bonds.lock().unwrap();
            let e = b.entry(*id).or_insert_with(|| new_bond(id));
            e.link_key = Some(*key);
            e.link_key_type = Some(key_type);
            if e.name.is_none() {
                e.name = name;
            }
        }
        self.persist();
    }

    pub fn upsert_le(&self, id: &DeviceId, keys: &LeKeys, name: Option<String>) {
        {
            let mut b = self.bonds.lock().unwrap();
            let e = b.entry(*id).or_insert_with(|| new_bond(id));
            e.le_ltk = Some(keys.ltk);
            e.le_ediv = keys.ediv;
            e.le_rand = keys.rand;
            e.le_irk = keys.irk;
            if e.name.is_none() {
                e.name = name;
            }
        }
        self.persist();
    }

    pub fn set_trusted(&self, id: &DeviceId, trusted: bool) -> bool {
        let found = match self.bonds.lock().unwrap().get_mut(id) {
            Some(e) => {
                e.trusted = trusted;
                true
            }
            None => false,
        };
        if found {
            self.persist();
        }
        found
    }

    pub fn touch_connected(&self, id: &DeviceId) {
        let found = match self.bonds.lock().unwrap().get_mut(id) {
            Some(e) => {
                e.last_connected = crate::device::now_ts();
                true
            }
            None => false,
        };
        if found {
            self.persist();
        }
    }

    pub fn remove(&self, id: &DeviceId) -> bool {
        let existed = self.bonds.lock().unwrap().remove(id).is_some();
        if existed {
            self.persist();
        }
        existed
    }

    pub fn set_name(&self, id: &DeviceId, name: &str) {
        let found = match self.bonds.lock().unwrap().get_mut(id) {
            Some(e) => {
                e.name = Some(name.to_string());
                true
            }
            None => false,
        };
        if found {
            self.persist();
        }
    }

    pub fn set_class(&self, id: &DeviceId, class: u32) {
        let found = match self.bonds.lock().unwrap().get_mut(id) {
            Some(e) => {
                e.class = class;
                true
            }
            None => false,
        };
        if found {
            self.persist();
        }
    }

    pub fn update_profiles(&self, id: &DeviceId, kind: ProfileKind) {
        let changed = match self.bonds.lock().unwrap().get_mut(id) {
            Some(e) if !e.profiles.contains(&kind) => {
                e.profiles.push(kind);
                true
            }
            _ => false,
        };
        if changed {
            self.persist();
        }
    }
}
