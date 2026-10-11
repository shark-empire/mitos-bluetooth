use crate::bonding::BondStore;
use crate::device::{AddressType, DeviceId, DeviceState, DeviceTable};
use crate::error::{hci_status_text, Error, Result};
use crate::events::{Event, EventBus, PairingMethod, PairingRequest};
use crate::hci::{ev, op, HciClient, HciEvent};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// BR/EDR Secure Simple Pairing: the HCI IO capabilities are 0..=3 (Core Vol 4 Part E, IO Capability Request Reply).
// 0x04 (KeyboardDisplay) exists only in the LE Security Manager and is rejected by BR/EDR controllers.
const IO_DISPLAY_YES_NO: u8 = 0x01;
const IO_NO_INPUT_NO_OUTPUT: u8 = 0x03;
/// Authentication_Requirements: general bonding, MITM protection not required by us (bit 0 clear).
const AUTH_GENERAL_BONDING: u8 = 0x04;

#[derive(Clone, Debug)]
pub struct PendingPairing {
    pub request: PairingRequest,
    pub created: Instant,
    pub mitm: bool,
}

pub struct PairingManager {
    pub hci: Arc<HciClient>,
    pub devices: Arc<DeviceTable>,
    pub bus: Arc<EventBus>,
    pub bonds: Arc<BondStore>,
    pub pending: Arc<Mutex<HashMap<DeviceId, PendingPairing>>>,
    pub io_capability: u8,
    pub auto_pin: bool,
    pub default_pin: String,
    pub just_works_auto: bool,
    /// What each peer told us during the current exchange: (IO capability, authentication requirements).
    remote: Mutex<HashMap<DeviceId, (u8, u8)>>,
}

fn bredr(addr: crate::device::Address) -> DeviceId {
    DeviceId { address: addr, address_type: AddressType::Bredr }
}

impl PairingManager {
    pub fn new(hci: Arc<HciClient>, devices: Arc<DeviceTable>, bus: Arc<EventBus>, bonds: Arc<BondStore>, auto_pin: bool, default_pin: String) -> Self {
        let pending: Arc<Mutex<HashMap<DeviceId, PendingPairing>>> = Arc::new(Mutex::new(HashMap::new()));
        // the janitor only watches a Weak reference, so it ends together with the manager
        let weak = Arc::downgrade(&pending);
        let bus2 = bus.clone();
        std::thread::Builder::new()
            .name("pairing-janitor".into())
            .spawn(move || loop {
                std::thread::sleep(Duration::from_secs(5));
                let Some(pending) = weak.upgrade() else { break };
                let expired: Vec<DeviceId> = {
                    let mut p = pending.lock().unwrap();
                    let dead: Vec<DeviceId> =
                        p.iter().filter(|(_, v)| v.created.elapsed() >= Duration::from_secs(35)).map(|(id, _)| *id).collect();
                    for id in &dead {
                        p.remove(id);
                    }
                    dead
                };
                for id in expired {
                    bus2.publish(Event::PairingComplete { id, success: false, error: Some("pairing request timed out".into()) });
                }
            })
            .ok();
        PairingManager {
            hci,
            devices,
            bus,
            bonds,
            pending,
            io_capability: IO_DISPLAY_YES_NO,
            auto_pin,
            default_pin,
            just_works_auto: true,
            remote: Mutex::new(HashMap::new()),
        }
    }

    fn ask(&self, id: DeviceId, method: PairingMethod, passkey: Option<u32>, mitm: bool) {
        let request = PairingRequest { device: id, method, passkey };
        self.pending.lock().unwrap().insert(id, PendingPairing { request: request.clone(), created: Instant::now(), mitm });
        self.bus.publish(Event::PairingRequested { request });
    }

    fn pin_reply(addr: crate::device::Address, pin: &str) -> Vec<u8> {
        let mut p = addr.0.to_vec();
        p.push(pin.len() as u8);
        let mut b = pin.as_bytes().to_vec();
        b.resize(16, 0);
        p.extend_from_slice(&b);
        p
    }

    /// Route pairing-related HCI events (called on the adapter dispatch thread).
    pub fn on_event(&self, ev: &HciEvent) {
        match ev.code {
            ev::LINK_KEY_REQUEST => {
                let addr = ev.addr(0);
                match self.bonds.get(&bredr(addr)).and_then(|b| b.link_key) {
                    Some(key) => {
                        let mut p = addr.0.to_vec();
                        p.extend_from_slice(&key);
                        let _ = self.hci.command(op::LINK_KEY_REQUEST_REPLY, &p);
                    }
                    None => {
                        let _ = self.hci.command(op::LINK_KEY_REQUEST_NEG_REPLY, &addr.0);
                    }
                }
            }
            ev::LINK_KEY_NOTIFICATION => {
                let addr = ev.addr(0);
                let id = bredr(addr);
                let mut key = [0u8; 16];
                for (dst, src) in key.iter_mut().zip(ev.bytes(6, 16)) {
                    *dst = *src;
                }
                let key_type = ev.u8(22);
                let name = self.devices.lock().unwrap().get(&id).and_then(|d| d.properties.alias.clone().or_else(|| d.properties.name.clone()));
                self.bonds.upsert_classic(&id, &key, key_type, name);
                if let Some(d) = self.devices.lock().unwrap().get_mut(&id) {
                    d.paired = true;
                    d.trusted = true;
                    d.state = DeviceState::Paired;
                }
                self.pending.lock().unwrap().remove(&id);
                self.remote.lock().unwrap().remove(&id);
                self.bus.publish(Event::PairingComplete { id, success: true, error: None });
            }
            ev::PIN_CODE_REQUEST => {
                let addr = ev.addr(0);
                if self.auto_pin {
                    let _ = self.hci.command(op::PIN_CODE_REQUEST_REPLY, &Self::pin_reply(addr, &self.default_pin));
                } else {
                    self.ask(bredr(addr), PairingMethod::PinCode, None, false);
                }
            }
            ev::IO_CAPABILITY_REQUEST => {
                let mut p = ev.addr(0).0.to_vec();
                p.push(self.io_capability);
                p.push(0x00); // OOB data not present
                p.push(AUTH_GENERAL_BONDING);
                let _ = self.hci.command(op::IO_CAPABILITY_REQUEST_REPLY, &p);
            }
            ev::IO_CAPABILITY_RESPONSE => {
                // bd_addr(6) io_capability(1) oob_present(1) authentication_requirements(1)
                self.remote.lock().unwrap().insert(bredr(ev.addr(0)), (ev.u8(6), ev.u8(8)));
            }
            ev::USER_CONFIRMATION_REQUEST => {
                let addr = ev.addr(0);
                let id = bredr(addr);
                let value = ev.u32(6);
                let (_, remote_auth) = self.remote.lock().unwrap().get(&id).copied().unwrap_or((IO_NO_INPUT_NO_OUTPUT, 0));
                let remote_wants_mitm = remote_auth & 0x01 != 0;
                // We never require MITM ourselves, so the numbers need checking by the user only when the peer
                // demands MITM protection and we are able to display/compare (Just Works otherwise).
                let can_compare = self.io_capability != IO_NO_INPUT_NO_OUTPUT;
                if self.just_works_auto && !(remote_wants_mitm && can_compare) {
                    let _ = self.hci.command(op::USER_CONFIRMATION_REQUEST_REPLY, &addr.0);
                } else {
                    self.ask(id, PairingMethod::NumericComparison, Some(value), remote_wants_mitm);
                }
            }
            ev::USER_PASSKEY_REQUEST => {
                self.ask(bredr(ev.addr(0)), PairingMethod::PasskeyEntry, None, true);
            }
            ev::USER_PASSKEY_NOTIFICATION => {
                // We display this passkey; the user types it on the remote keyboard.
                let request = PairingRequest { device: bredr(ev.addr(0)), method: PairingMethod::JustWorks, passkey: Some(ev.u32(6)) };
                self.bus.publish(Event::PairingRequested { request });
            }
            ev::SIMPLE_PAIRING_COMPLETE => {
                let status = ev.u8(0);
                if status != 0 {
                    let id = bredr(ev.addr(1));
                    self.pending.lock().unwrap().remove(&id);
                    self.remote.lock().unwrap().remove(&id);
                    let error = format!("pairing failed: {}", hci_status_text(status));
                    self.bus.publish(Event::PairingComplete { id, success: false, error: Some(error) });
                }
            }
            ev::REMOTE_OOB_DATA_REQUEST => {
                let _ = self.hci.command(op::REMOTE_OOB_DATA_REQUEST_NEG_REPLY, &ev.addr(0).0);
            }
            _ => {}
        }
    }

    /// Authentication Complete for a link (the manager resolves the handle to a device).
    /// Success needs no action here: the link key notification already reported the pairing.
    pub fn on_auth_complete(&self, id: Option<DeviceId>, status: u8) {
        let Some(id) = id else { return };
        if status == 0 {
            return;
        }
        self.pending.lock().unwrap().remove(&id);
        self.remote.lock().unwrap().remove(&id);
        let error = if status == 0x06 {
            "the device no longer has our pairing (pin or key missing): remove it and pair again".to_string()
        } else {
            format!("authentication failed: {}", hci_status_text(status))
        };
        self.bus.publish(Event::PairingComplete { id, success: false, error: Some(error) });
    }

    pub fn confirm(&self, device: &DeviceId, accept: bool) -> Result<()> {
        self.pending.lock().unwrap().remove(device);
        let reply_op = if accept { op::USER_CONFIRMATION_REQUEST_REPLY } else { op::USER_CONFIRMATION_REQUEST_NEG_REPLY };
        self.hci.command(reply_op, &device.address.0)?;
        Ok(())
    }

    pub fn provide_pin(&self, device: &DeviceId, pin: &str) -> Result<()> {
        if pin.is_empty() || pin.len() > 16 {
            return Err(Error::InvalidArgument("pin must be 1..=16 bytes".into()));
        }
        self.pending.lock().unwrap().remove(device);
        self.hci.command(op::PIN_CODE_REQUEST_REPLY, &Self::pin_reply(device.address, pin))?;
        Ok(())
    }

    pub fn provide_passkey(&self, device: &DeviceId, passkey: u32) -> Result<()> {
        if passkey > 999_999 {
            return Err(Error::InvalidArgument("passkey out of range".into()));
        }
        self.pending.lock().unwrap().remove(device);
        let mut p = device.address.0.to_vec();
        p.extend_from_slice(&passkey.to_le_bytes());
        self.hci.command(op::USER_PASSKEY_REQUEST_REPLY, &p)?;
        Ok(())
    }

    pub fn cancel(&self, device: &DeviceId) -> Result<()> {
        let addr = device.address;
        self.pending.lock().unwrap().remove(device);
        self.remote.lock().unwrap().remove(device);
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

    /// Authenticate an existing link with the stored link key (the answer to the controller's Link Key Request
    /// is sent by `on_event`) and wait for the outcome.
    pub fn authenticate(&self, handle: u16, timeout: Duration) -> Result<()> {
        let waiter = self.hci.expect_event(move |e| e.code == ev::AUTHENTICATION_COMPLETE && e.u16(1) == handle);
        self.request_auth(handle)?;
        let done = waiter.wait(timeout)?;
        match done.u8(0) {
            0 => Ok(()),
            0x06 => Err(Error::PairingFailed("the device no longer has our pairing (pin or key missing): remove it and pair again".into())),
            s => Err(Error::PairingFailed(format!("authentication failed: {}", hci_status_text(s)))),
        }
    }
}
