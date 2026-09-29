use crate::bonding::BondStore;
use crate::device::{Device, DeviceId, DeviceTable};
use crate::error::{Error, Result};
use crate::events::{Event, EventBus, PairingMethod, PairingRequest};
use crate::hci::{ev, op, HciClient, HciEvent};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct PendingPairing { pub request: PairingRequest, pub created: Instant, pub mitm: bool }

pub struct PairingManager {
    pub hci: Arc<HciClient>,
    pub devices: Arc<DeviceTable>,
    pub bus: Arc<EventBus>,
    pub bonds: Arc<BondStore>,
    pub pending: Arc<Mutex<HashMap<DeviceId, PendingPairing>>>,
    pub io_capability: u8,          // 0x04 KeyboardDisplay
    pub auto_pin: bool,
    pub default_pin: String,
    pub just_works_auto: bool,
}

impl PairingManager {
    pub fn new(hci: Arc<HciClient>, devices: Arc<DeviceTable>, bus: Arc<EventBus>, bonds: Arc<BondStore>) -> Self {
        let pending: Arc<Mutex<HashMap<DeviceId, PendingPairing>>> = Arc::new(Mutex::new(HashMap::new()));
        let p2 = pending.clone();
        let bus2 = bus.clone();
        std::thread::Builder::new().name("pairing-janitor".into()).spawn(move || loop {
            std::thread::sleep(Duration::from_secs(5));
            let expired: Vec<DeviceId> = {
                let mut p = p2.lock().unwrap();
                let dead: Vec<DeviceId> = p.iter()
                    .filter(|(_, v)| v.created.elapsed() >= Duration::from_secs(35))
                    .map(|(id, _)| *id)
                    .collect();
                for id in &dead { p.remove(id); }
                dead
            };
            for id in expired {
                bus2.publish(Event::PairingComplete { id, success: false, error: Some("pairing request timed out".into()) });
            }
        }).ok();
        PairingManager { hci, devices, bus, bonds, pending, io_capability: 0x04, auto_pin: true, default_pin: "0000".into(), just_works_auto: true }
    }

    /// Route pairing-related HCI events (called on the adapter core thread).
    pub fn on_event(&self, ev: &HciEvent) {
        match ev.code {
            ev::LINK_KEY_REQUEST => {
                let addr = ev.addr(0);
                let id = DeviceId { address: addr, address_type: crate::device::AddressType::Bredr };
                let bond = self.bonds.get(&id);
                match bond.and_then(|b| b.link_key) {
                    Some(key) => {
                        let mut p = addr.0.to_vec();
                        p.extend_from_slice(&key);
                        let _ = self.hci.command(op::LINK_KEY_REQUEST_REPLY, &p);
                    }
                    None => { let _ = self.hci.command(op::LINK_KEY_REQUEST_NEG_REPLY, &addr.0); }
                }
            }
            ev::LINK_KEY_NOTIFICATION => {
                let addr = ev.addr(0);
                let key: [u8; 16] = ev.bytes(6, 16).try_into().unwrap_or([0; 16]);
                let key_type = ev.u8(22);
                let id = DeviceId { address: addr, address_type: crate::device::AddressType::Bredr };
                let name = self.devices.lock().unwrap().get(&id).map(|d| d.display_name());
                self.bonds.upsert_classic(&id, &key, key_type, name);
                {
                    let mut ds = self.devices.lock().unwrap();
                    if let Some(d) = ds.get_mut(&id) { d.paired = true; d.state = crate::device::DeviceState::Paired; }
                }
                self.pending.lock().unwrap().remove(&id);
                self.bus.publish(Event::PairingComplete { id, success: true, error: None });
            }
            ev::PIN_CODE_REQUEST => {
                let addr = ev.addr(0);
                let id = DeviceId { address: addr, address_type: crate::device::AddressType::Bredr };
                if self.auto_pin {
                    let pin = self.default_pin.clone();
                    let mut p = addr.0.to_vec();
                    p.push(pin.len() as u8);
                    let mut b = pin.into_bytes();
                    b.resize(16, 0);
                    p.extend_from_slice(&b);
                    let _ = self.hci.command(op::PIN_CODE_REQUEST_REPLY, &p);
                } else {
                    self.pending.lock().unwrap().insert(id, PendingPairing {
                        request: PairingRequest { device: id, method: PairingMethod::PinCode, passkey: None },
                        created: Instant::now(), mitm: false,
                    });
                    self.bus.publish(Event::PairingRequested { request: PairingRequest { device: id, method: PairingMethod::PinCode, passkey: None } });
                }
            }
            ev::IO_CAPABILITY_REQUEST => {
                let addr = ev.addr(0);
                let mut p = addr.0.to_vec();
                p.push(self.io_capability);
                p.push(0x00); // OOB not present
                p.push(0x04); // auth req: general bonding, no MITM (keyboards force MITM on their side)
                let _ = self.hci.command(op::IO_CAPABILITY_REQUEST_REPLY, &p);
            }
            ev::IO_CAPABILITY_RESPONSE => {
                let addr = ev.addr(0);
                let id = DeviceId { address: addr, address_type: crate::device::AddressType::Bredr };
                let auth = ev.u8(8);
                let mut p = self.pending.lock().unwrap();
                if let Some(v) = p.get_mut(&id) { v.mitm = auth & 0x01 != 0; }
            }
            ev::USER_CONFIRMATION_REQUEST => {
                let addr = ev.addr(0);
                let id = DeviceId { address: addr, address_type: crate::device::AddressType::Bredr };
                let value = ev.u32(6);
                let mitm = self.pending.lock().unwrap().get(&id).map(|v| v.mitm).unwrap_or(false);
                if self.just_works_auto && !mitm {
                    let _ = self.hci.command(op::USER_CONFIRMATION_REQUEST_REPLY, &addr.0);
                } else {
                    self.pending.lock().unwrap().insert(id.clone(), PendingPairing {
                        request: PairingRequest { device: id, method: PairingMethod::NumericComparison, passkey: Some(value) },
                        created: Instant::now(), mitm,
                    });
                    self.bus.publish(Event::PairingRequested { request: PairingRequest { device: id, method: PairingMethod::NumericComparison, passkey: Some(value) } });
                }
            }
            ev::USER_PASSKEY_REQUEST => {
                let addr = ev.addr(0);
                let id = DeviceId { address: addr, address_type: crate::device::AddressType::Bredr };
                self.pending.lock().unwrap().insert(id.clone(), PendingPairing {
                    request: PairingRequest { device: id, method: PairingMethod::PasskeyEntry, passkey: None },
                    created: Instant::now(), mitm: true,
                });
                self.bus.publish(Event::PairingRequested { request: PairingRequest { device: id, method: PairingMethod::PasskeyEntry, passkey: None } });
            }
            ev::USER_PASSKEY_NOTIFICATION => {
                // We display this passkey; the user types it on the remote keyboard.
                let addr = ev.addr(0);
                let id = DeviceId { address: addr, address_type: crate::device::AddressType::Bredr };
                let value = ev.u32(6);
                self.bus.publish(Event::PairingRequested { request: PairingRequest { device: id, method: PairingMethod::JustWorks, passkey: Some(value) } });
            }
            ev::SIMPLE_PAIRING_COMPLETE => {
                let status = ev.u8(0);
                let addr = ev.addr(1);
                let id = DeviceId { address: addr, address_type: crate::device::AddressType::Bredr };
                if status != 0 {
                    self.pending.lock().unwrap().remove(&id);
                    self.bus.publish(Event::PairingComplete { id, success: false, error: Some(format!("ssp failed: status {status}")) });
                }
            }
            ev::AUTHENTICATION_COMPLETE => {
                let status = ev.u8(0);
                if status != 0 && status != 0x06 {
                    // find device by handle
                    let handle = ev.u16(1);
                    if let Some(id) = self.hci_device(handle) {
                        self.pending.lock().unwrap().remove(&id);
                        self.bus.publish(Event::PairingComplete { id, success: false, error: Some(format!("authentication failed: status {status}")) });
                    }
                }
            }
            ev::REMOTE_OOB_DATA_REQUEST => {
                let addr = ev.addr(0);
                let _ = self.hci.command(op::REMOTE_OOB_DATA_REQUEST_NEG_REPLY, &addr.0);
            }
            _ => {}
        }
    }

    fn hci_device(&self, _handle: u16) -> Option<DeviceId> { None } // core keeps handle maps; failures surface via other events

    // ------- GUI-driven API -------
    pub fn confirm(&self, device: &DeviceId, accept: bool) -> Result<()> {
        let addr = device.address;
        self.pending.lock().unwrap().remove(device);
        if accept { self.hci.command(op::USER_CONFIRMATION_REQUEST_REPLY, &addr.0) }
        else { self.hci.command(op::USER_CONFIRMATION_REQUEST_NEG_REPLY, &addr.0) }
    }
    pub fn provide_pin(&self, device: &DeviceId, pin: &str) -> Result<()> {
        if pin.is_empty() || pin.len() > 16 { return Err(Error::InvalidArgument("pin must be 1..=16 bytes".into())); }
        let addr = device.address;
        self.pending.lock().unwrap().remove(device);
        let mut p = addr.0.to_vec();
        p.push(pin.len() as u8);
        let mut b = pin.as_bytes().to_vec();
        b.resize(16, 0);
        p.extend_from_slice(&b);
        self.hci.command(op::PIN_CODE_REQUEST_REPLY, &p)
    }
    pub fn provide_passkey(&self, device: &DeviceId, passkey: u32) -> Result<()> {
        if passkey > 999_999 { return Err(Error::InvalidArgument("passkey out of range".into())); }
        let addr = device.address;
        self.pending.lock().unwrap().remove(device);
        let mut p = addr.0.to_vec();
        p.extend_from_slice(&passkey.to_le_bytes());
        self.hci.command(op::USER_PASSKEY_REQUEST_REPLY, &p)
    }
    pub fn cancel(&self, device: &DeviceId) -> Result<()> {
        let addr = device.address;
        self.pending.lock().unwrap().remove(device);
        let _ = self.hci.command(op::USER_CONFIRMATION_REQUEST_NEG_REPLY, &addr.0);
        let _ = self.hci.command(op::USER_PASSKEY_REQUEST_NEG_REPLY, &addr.0);
        let _ = self.hci.command(op::PIN_CODE_REQUEST_NEG_REPLY, &addr.0);
        self.bus.publish(Event::PairingComplete { id: *device, success: false, error: Some("cancelled".into()) });
        Ok(())
    }
    /// Trigger authentication on an existing ACL link to force pairing.
    pub fn request_auth(&self, handle: u16) -> Result<()> {
        match self.hci.command_status(op::AUTHENTICATION_REQUESTED, &handle.to_le_bytes()) {
            Ok(()) => Ok(()),
            Err(Error::Hci { status: 0x0c, .. }) => Ok(()), // command disallowed if auth already running
            Err(e) => Err(e),
        }
    }
}
