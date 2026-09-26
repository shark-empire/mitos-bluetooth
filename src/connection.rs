use crate::bonding::BondStore;
use crate::device::{now_ts, AddressType, Device, DeviceClass, DeviceId, DeviceState, DeviceTable};
use crate::error::{hci_status_text, Error, Result};
use crate::events::{Event, EventBus};
use crate::gatt::GattManager;
use crate::hci::{ev, op, HciClient, HciEvent};
use crate::l2cap::L2cap;
use crate::profile::{ProfileKind, ProfileManager};
use crate::smp::Smp;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone, Copy, PartialEq, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ConnectionState { Connecting, Connected, Disconnecting }

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnInfo {
    pub device: DeviceId,
    pub handle: u16,
    pub le: bool,
    pub state: ConnectionState,
    pub encrypted: bool,
    pub profiles: Vec<ProfileKind>,
    pub since: u64,
}

pub struct ConnectionManager {
    pub hci: Arc<HciClient>,
    pub l2: Arc<L2cap>,
    pub smp: Arc<Smp>,
    pub gatt: Arc<GattManager>,
    pub profiles: Arc<ProfileManager>,
    pub devices: Arc<DeviceTable>,
    pub bus: Arc<EventBus>,
    pub bonds: Arc<BondStore>,
    pub conns: Mutex<HashMap<DeviceId, ConnInfo>>,
    pub by_handle: Mutex<HashMap<u16, DeviceId>>,
}

impl ConnectionManager {
    pub fn new(hci: Arc<HciClient>, l2: Arc<L2cap>, smp: Arc<Smp>, gatt: Arc<GattManager>,
               profiles: Arc<ProfileManager>, devices: Arc<DeviceTable>, bus: Arc<EventBus>,
               bonds: Arc<BondStore>) -> Self {
        ConnectionManager { hci, l2, smp, gatt, profiles, devices, bus, bonds,
                            conns: Mutex::new(HashMap::new()), by_handle: Mutex::new(HashMap::new()) }
    }

    pub fn list(&self) -> Vec<ConnInfo> {
        let mut v: Vec<ConnInfo> = self.conns.lock().unwrap().values().cloned().collect();
        v.sort_by_key(|c| c.device); v
    }
    pub fn get(&self, id: &DeviceId) -> Option<ConnInfo> { self.conns.lock().unwrap().get(id).cloned() }
    pub fn handle_of(&self, id: &DeviceId) -> Option<u16> {
        self.conns.lock().unwrap().get(id).filter(|c| c.state == ConnectionState::Connected).map(|c| c.handle)
    }

    /// Establish (or reuse) an ACL link. Returns the connection handle.
    pub fn connect_acl(&self, id: &DeviceId, timeout: Duration) -> Result<u16> {
        if let Some(h) = self.handle_of(id) { return Ok(h); }
        {
            let mut ds = self.devices.lock().unwrap();
            let d = ds.entry(*id).or_insert_with(|| Device::new(*id));
            d.state = DeviceState::Connecting;
        }
        {
            let mut c = self.conns.lock().unwrap();
            c.entry(*id).and_modify(|i| i.state = ConnectionState::Connecting)
                .or_insert(ConnInfo { device: *id, handle: 0, le: id.address_type != AddressType::Bredr,
                                      state: ConnectionState::Connecting, encrypted: false, profiles: Vec::new(), since: now_ts() });
        }
        let target = id.address; // closures below must own their captures ('static)
        let complete = if id.address_type == AddressType::Bredr {
            let mut p = Vec::with_capacity(13);
            p.extend_from_slice(&target.0);
            p.extend_from_slice(&0xCC18u16.to_le_bytes()); // DM1/DH1/DM3/DH3/DM5/DH5 (+EDR)
            p.push(0x02); // page scan repetition mode R2
            p.push(0x00);
            p.extend_from_slice(&0u16.to_le_bytes()); // clock offset: unknown
            p.push(0x01); // allow role switch
            self.hci.command_status(op::CREATE_CONNECTION, &p)?;
            self.hci.wait_event(move |e| e.code == ev::CONNECTION_COMPLETE && e.addr(1) == target, timeout)?
        } else {
            let mut p = Vec::with_capacity(25);
            p.extend_from_slice(&0x0060u16.to_le_bytes()); // scan interval
            p.extend_from_slice(&0x0030u16.to_le_bytes()); // scan window
            p.push(0x00); // initiator filter: use peer address
            p.push(if id.address_type == AddressType::LeRandom { 0x01 } else { 0x00 });
            p.extend_from_slice(&target.0);
            p.push(0x00); // own address type: public
            p.extend_from_slice(&0x0018u16.to_le_bytes()); // conn interval min
            p.extend_from_slice(&0x0028u16.to_le_bytes()); // conn interval max
            p.extend_from_slice(&0u16.to_le_bytes()); // latency
            p.extend_from_slice(&0x0048u16.to_le_bytes()); // supervision timeout
            p.extend_from_slice(&0u16.to_le_bytes()); // min CE length
            p.extend_from_slice(&0u16.to_le_bytes()); // max CE length
            self.hci.command_status(op::LE_CREATE_CONNECTION, &p)?;
            self.hci.wait_event(move |e| e.code == ev::LE_META_EVENT && e.le_sub() == ev::LE_CONNECTION_COMPLETE
                                           && e.addr(6) == target, timeout)?
        };
        if id.address_type == AddressType::Bredr {
            let status = complete.u8(0);
            if status != 0 { return Err(self.fail(id, status)); }
            let handle = complete.u16(1);
            self.register(handle, *id, false);
            Ok(handle)
        } else {
            let status = complete.u8(1);
            if status != 0 {
                let _ = self.hci.command(op::LE_CREATE_CONNECTION_CANCEL, &[]);
                return Err(self.fail(id, status));
            }
            let handle = complete.u16(2);
            self.register(handle, *id, true);
            Ok(handle)
        }
    }

    fn fail(&self, id: &DeviceId, status: u8) -> Error {
        self.conns.lock().unwrap().remove(id);
        self.devices.lock().unwrap().get_mut(id).map(|d| d.state = DeviceState::Discovered);
        Error::ConnectionFailed(format!("status 0x{status:02x} ({})", hci_status_text(status)))
    }

    fn register(&self, handle: u16, id: DeviceId, le: bool) {
        {
            let mut c = self.conns.lock().unwrap();
            c.entry(id).and_modify(|i| { i.handle = handle; i.state = ConnectionState::Connected; i.le = le; })
                .or_insert(ConnInfo { device: id, handle, le, state: ConnectionState::Connected,
                                      encrypted: false, profiles: Vec::new(), since: now_ts() });
        }
        self.by_handle.lock().unwrap().insert(handle, id);
        self.l2.set_device(handle, id);
        self.devices.lock().unwrap().get_mut(&id).map(|d| { d.connected = true; d.state = DeviceState::Connected; });
        if le {
            self.smp.attach(handle, id);
            self.gatt.attach(handle, id);
            // re-encrypt using the stored LTK if we have an LE bond
            if self.bonds.get(&id).and_then(|b| b.le_ltk).is_some() {
                let smp = self.smp.clone();
                std::thread::spawn(move || { let _ = smp.encrypt_bond(handle); });
            }
        }
    }

    /// Connect the ACL link (if needed) and bring a profile up on top of it.
    pub fn connect_profile(&self, id: &DeviceId, kind: ProfileKind) -> Result<()> {
        let handle = self.connect_acl(id, Duration::from_secs(15))?;
        let le = id.address_type != AddressType::Bredr;
        self.profiles.connect(id, handle, le, kind)?;
        {
            let mut c = self.conns.lock().unwrap();
            if let Some(i) = c.get_mut(id) { if !i.profiles.contains(&kind) { i.profiles.push(kind); } }
        }
        self.bonds.update_profiles(id, kind);
        self.bonds.touch_connected(id);
        self.devices.lock().unwrap().get_mut(id).map(|d| { if !d.profiles.contains(&kind) { d.profiles.push(kind); } });
        self.bus.publish(Event::DeviceConnected { id: *id, profiles: vec![kind] });
        Ok(())
    }

    pub fn disconnect(&self, id: &DeviceId, reason: u8) -> Result<()> {
        let handle = self.conns.lock().unwrap().get(id).map(|c| c.handle)
            .ok_or_else(|| Error::NotFound("no connection".into()))?;
        {
            let mut c = self.conns.lock().unwrap();
            c.entry(*id).and_modify(|i| i.state = ConnectionState::Disconnecting);
        }
        let mut p = handle.to_le_bytes().to_vec();
        p.push(reason);
        self.hci.command_status(op::DISCONNECT, &p)?;
        // the dispatch thread also cleans up on the event; both paths are idempotent
        let _ = self.hci.wait_event(move |e| e.code == ev::DISCONNECTION_COMPLETE && e.u16(1) == handle,
                                     Duration::from_secs(5));
        self.cleanup(handle, format!("disconnected (reason 0x{reason:02x})"));
        Ok(())
    }

    fn cleanup(&self, handle: u16, reason: String) {
        let Some(id) = self.by_handle.lock().unwrap().remove(&handle) else { return };
        self.conns.lock().unwrap().remove(&id);
        self.l2.cleanup_handle(handle);   // notifies L2CAP channel consumers (HID etc.)
        self.profiles.disconnect(&id);
        self.smp.detach(handle);
        self.gatt.detach(handle);
        self.devices.lock().unwrap().get_mut(&id).map(|d| { d.connected = false; d.state = DeviceState::Disconnected; });
        self.bus.publish(Event::DeviceDisconnected { id, reason });
    }

    /// Reconnect a trusted device with backoff.
    pub fn reconnect(&self, id: &DeviceId) -> Result<u16> {
        let mut delay = Duration::from_millis(500);
        for _ in 0..3 {
            if let Ok(h) = self.connect_acl(id, Duration::from_secs(10)) { return Ok(h); }
            std::thread::sleep(delay);
            delay *= 2;
        }
        Err(Error::ConnectionFailed("reconnect attempts exhausted".into()))
    }

    /// Event routing — called on the adapter dispatch thread.
    pub fn on_event(&self, ev: &HciEvent) {
        match ev.code {
            ev::CONNECTION_REQUEST => self.on_connection_request(ev),
            ev::CONNECTION_COMPLETE => self.on_connection_complete(ev, false),
            ev::LE_META_EVENT if ev.le_sub() == ev::LE_CONNECTION_COMPLETE => self.on_connection_complete(ev, true),
            ev::DISCONNECTION_COMPLETE => {
                if ev.u8(0) == 0 {
                    self.cleanup(ev.u16(1), format!("remote terminated (reason 0x{:02x})", ev.u8(3)));
                }
            }
            ev::ENCRYPTION_CHANGE => {
                let handle = ev.u16(1);
                let enabled = ev.u8(3) != 0;
                if ev.u8(0) != 0 {
                    if let Some(id) = self.by_handle.lock().unwrap().get(&handle).copied() {
                        self.bus.publish(Event::PairingComplete { id, success: false,
                            error: Some(format!("encryption failed: status 0x{:02x}", ev.u8(0))) });
                    }
                }
                if let Some(id) = self.by_handle.lock().unwrap().get(&handle).copied() {
                    if let Some(c) = self.conns.lock().unwrap().get_mut(&id) { c.encrypted = enabled; }
                }
            }
            ev::AUTHENTICATION_COMPLETE => {
                let status = ev.u8(0);
                if status != 0 && status != 0x06 { // 0x06 = pin/key missing -> normal start of pairing
                    let handle = ev.u16(1);
                    if let Some(id) = self.by_handle.lock().unwrap().get(&handle).copied() {
                        self.bus.publish(Event::PairingComplete { id, success: false,
                            error: Some(format!("authentication failed: 0x{status:02x} ({})", hci_status_text(status))) });
                    }
                }
            }
            _ => {}
        }
    }

    fn on_connection_request(&self, ev: &HciEvent) {
        let addr = ev.addr(0);
        let class = u32::from_le_bytes([ev.u8(6), ev.u8(7), ev.u8(8), 0]);
        let link_type = ev.u8(9);
        if link_type != 0 {
            // SCO/eSCO — audio manager territory (audio batch). Reject politely for now.
            let mut p = addr.0.to_vec();
            p.push(0x13);
            p.extend_from_slice(&0u32.to_le_bytes());          // tx bandwidth
            p.extend_from_slice(&0u32.to_le_bytes());          // rx bandwidth
            p.extend_from_slice(&0x0060u16.to_le_bytes());     // voice setting: CVSD
            p.push(0x02);                                      // retransmission effort
            p.extend_from_slice(&0x03FFu16.to_le_bytes());     // packet types
            let _ = self.hci.command_status(op::REJECT_SYNCHRONOUS_CONNECTION, &p);
            return;
        }
        let id = DeviceId { address: addr, address_type: AddressType::Bredr };
        {
            let mut ds = self.devices.lock().unwrap();
            ds.entry(id).or_insert_with(|| { let mut d = Device::new(id); d.properties.class = DeviceClass(class); d });
        }
        let mut p = addr.0.to_vec();
        p.push(0x00); // role: master
        let _ = self.hci.command_status(op::ACCEPT_CONNECTION_REQUEST, &p);
    }

    fn on_connection_complete(&self, ev: &HciEvent, le: bool) {
        let (status, handle, addr, addr_type) = if le {
            (ev.u8(1), ev.u16(2), ev.addr(6), if ev.u8(5) == 1 { AddressType::LeRandom } else { AddressType::LePublic })
        } else {
            (ev.u8(0), ev.u16(1), ev.addr(3), AddressType::Bredr)
        };
        if status != 0 { return; } // outgoing failure: surfaced by connect_acl
        if self.by_handle.lock().unwrap().contains_key(&handle) { return; }
        let id = DeviceId { address: addr, address_type: addr_type };
        self.register(handle, id, le);
        let d = self.devices.lock().unwrap().get(&id).cloned();
        if let Some(d) = d { self.bus.publish(Event::DeviceUpdated { device: d }); }
    }
}