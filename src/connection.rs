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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ConnectionState {
    Connecting,
    Connected,
    Disconnecting,
}

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

/// Everything a [`ConnectionManager`] works with.
pub struct ConnectionDeps {
    pub hci: Arc<HciClient>,
    pub l2: Arc<L2cap>,
    pub smp: Arc<Smp>,
    pub gatt: Arc<GattManager>,
    pub profiles: Arc<ProfileManager>,
    pub devices: Arc<DeviceTable>,
    pub bus: Arc<EventBus>,
    pub bonds: Arc<BondStore>,
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
    /// May devices we have no bond with connect to us? Off when `trusted_only_connect` is set, except
    /// while the adapter is discoverable (that is when a new device is supposed to find us).
    accept_unbonded: AtomicBool,
}

impl ConnectionManager {
    pub fn new(deps: ConnectionDeps, trusted_only: bool) -> Self {
        let ConnectionDeps { hci, l2, smp, gatt, profiles, devices, bus, bonds } = deps;
        ConnectionManager {
            hci,
            l2,
            smp,
            gatt,
            profiles,
            devices,
            bus,
            bonds,
            conns: Mutex::new(HashMap::new()),
            by_handle: Mutex::new(HashMap::new()),
            accept_unbonded: AtomicBool::new(!trusted_only),
        }
    }

    pub fn set_accept_unbonded(&self, accept: bool) {
        self.accept_unbonded.store(accept, Ordering::Relaxed);
    }

    pub fn list(&self) -> Vec<ConnInfo> {
        let mut v: Vec<ConnInfo> = self.conns.lock().unwrap().values().cloned().collect();
        v.sort_by_key(|c| c.device);
        v
    }

    pub fn get(&self, id: &DeviceId) -> Option<ConnInfo> {
        self.conns.lock().unwrap().get(id).cloned()
    }

    pub fn handle_of(&self, id: &DeviceId) -> Option<u16> {
        self.conns.lock().unwrap().get(id).filter(|c| c.state == ConnectionState::Connected).map(|c| c.handle)
    }

    pub fn device_of(&self, handle: u16) -> Option<DeviceId> {
        self.by_handle.lock().unwrap().get(&handle).copied()
    }

    fn failure(status: u8) -> Error {
        Error::ConnectionFailed(format!("status 0x{status:02x} ({})", hci_status_text(status)))
    }

    /// Re-establish link security for a bonded device: authenticate with the stored link key (BR/EDR, encryption
    /// follows from the Authentication Complete event) or start encryption with the stored LTK (LE).
    /// With `wait` the call returns once the link is encrypted (or after a timeout).
    fn ensure_encrypted(&self, handle: u16, wait: bool) {
        let Some(id) = self.device_of(handle) else { return };
        if self.get(&id).is_some_and(|c| c.encrypted) {
            return;
        }
        let Some(bond) = self.bonds.get(&id) else { return };
        if id.address_type == AddressType::Bredr {
            if bond.link_key.is_none() {
                return;
            }
            match self.hci.command_status(op::AUTHENTICATION_REQUESTED, &handle.to_le_bytes()) {
                Ok(()) => {}
                Err(Error::Hci { status: 0x0c, .. }) => {} // an authentication is already running
                Err(e) => {
                    eprintln!("[bt] authentication request failed: {e}");
                    return;
                }
            }
            if wait {
                self.wait_encrypted(&id, Duration::from_secs(8));
            }
        } else if bond.le_ltk.is_some() {
            if wait {
                if let Err(e) = self.smp.encrypt_bond(handle) {
                    eprintln!("[bt] could not encrypt the le link: {e}");
                }
            } else {
                let smp = self.smp.clone();
                std::thread::spawn(move || {
                    let _ = smp.encrypt_bond(handle);
                });
            }
        }
    }

    fn wait_encrypted(&self, id: &DeviceId, timeout: Duration) {
        let start = Instant::now();
        while start.elapsed() < timeout {
            match self.get(id) {
                Some(c) if !c.encrypted => std::thread::sleep(Duration::from_millis(50)),
                _ => return,
            }
        }
    }

    /// Establish (or reuse) an ACL link. Returns the connection handle.
    pub fn connect_acl(&self, id: &DeviceId, timeout: Duration) -> Result<u16> {
        if let Some(h) = self.handle_of(id) {
            return Ok(h);
        }
        self.devices.lock().unwrap().entry(*id).or_insert_with(|| Device::new(*id)).state = DeviceState::Connecting;
        self.conns
            .lock()
            .unwrap()
            .entry(*id)
            .and_modify(|i| i.state = ConnectionState::Connecting)
            .or_insert(ConnInfo {
                device: *id,
                handle: 0,
                le: id.address_type != AddressType::Bredr,
                state: ConnectionState::Connecting,
                encrypted: false,
                profiles: Vec::new(),
                since: now_ts(),
            });
        match self.try_connect(id, timeout) {
            Ok(h) => Ok(h),
            Err(e) => {
                self.abort_connect(id);
                Err(e)
            }
        }
    }

    /// Forget a connection attempt that did not produce a link.
    fn abort_connect(&self, id: &DeviceId) {
        let mut c = self.conns.lock().unwrap();
        if c.get(id).is_some_and(|i| i.state == ConnectionState::Connecting) {
            c.remove(id);
        }
        drop(c);
        if let Some(d) = self.devices.lock().unwrap().get_mut(id) {
            d.state = DeviceState::Discovered;
        }
    }

    fn try_connect(&self, id: &DeviceId, timeout: Duration) -> Result<u16> {
        let target = id.address; // closures below must own their captures ('static)
        if id.address_type == AddressType::Bredr {
            // register for the answer first: it must not be able to arrive before we listen
            let waiter = self.hci.expect_event(move |e| e.code == ev::CONNECTION_COMPLETE && e.addr(3) == target);
            let mut p = Vec::with_capacity(13);
            p.extend_from_slice(&target.0);
            p.extend_from_slice(&0xCC18u16.to_le_bytes()); // DM1/DH1/DM3/DH3/DM5/DH5 (+EDR)
            p.push(0x02); // page scan repetition mode R2
            p.push(0x00);
            p.extend_from_slice(&0u16.to_le_bytes()); // clock offset: unknown
            p.push(0x01); // allow role switch
            self.hci.command_status(op::CREATE_CONNECTION, &p)?;
            let complete = match waiter.wait(timeout) {
                Ok(c) => c,
                Err(e) => {
                    let _ = self.hci.command(op::CREATE_CONNECTION_CANCEL, &target.0);
                    return Err(e);
                }
            };
            // Connection Complete: status(1) handle(2) bd_addr(6) link_type(1) encryption(1)
            let status = complete.u8(0);
            if status != 0 {
                return Err(Self::failure(status));
            }
            let handle = complete.u16(1);
            self.register(handle, *id, false);
            Ok(handle)
        } else {
            let waiter = self.hci.expect_event(move |e| {
                e.code == ev::LE_META_EVENT && e.le_sub() == ev::LE_CONNECTION_COMPLETE && e.addr(6) == target
            });
            let mut p = Vec::with_capacity(25);
            p.extend_from_slice(&0x0060u16.to_le_bytes()); // scan interval
            p.extend_from_slice(&0x0030u16.to_le_bytes()); // scan window
            p.push(0x00); // initiator filter: use peer address
            p.push(u8::from(id.address_type == AddressType::LeRandom));
            p.extend_from_slice(&target.0);
            p.push(0x00); // own address type: public
            p.extend_from_slice(&0x0018u16.to_le_bytes()); // conn interval min
            p.extend_from_slice(&0x0028u16.to_le_bytes()); // conn interval max
            p.extend_from_slice(&0u16.to_le_bytes()); // latency
            p.extend_from_slice(&0x0048u16.to_le_bytes()); // supervision timeout
            p.extend_from_slice(&0u16.to_le_bytes()); // min CE length
            p.extend_from_slice(&0u16.to_le_bytes()); // max CE length
            self.hci.command_status(op::LE_CREATE_CONNECTION, &p)?;
            let complete = match waiter.wait(timeout) {
                Ok(c) => c,
                Err(e) => {
                    // an LE connection attempt has no timeout of its own: stop it
                    let _ = self.hci.command(op::LE_CREATE_CONNECTION_CANCEL, &[]);
                    return Err(e);
                }
            };
            // LE Connection Complete: subevent(1) status(1) handle(2) role(1) peer_addr_type(1) peer_addr(6) ...
            let status = complete.u8(1);
            if status != 0 {
                return Err(Self::failure(status));
            }
            let handle = complete.u16(2);
            self.register(handle, *id, true);
            Ok(handle)
        }
    }

    fn register(&self, handle: u16, id: DeviceId, le: bool) {
        self.conns
            .lock()
            .unwrap()
            .entry(id)
            .and_modify(|i| {
                i.handle = handle;
                i.state = ConnectionState::Connected;
                i.le = le;
            })
            .or_insert(ConnInfo {
                device: id,
                handle,
                le,
                state: ConnectionState::Connected,
                encrypted: false,
                profiles: Vec::new(),
                since: now_ts(),
            });
        self.by_handle.lock().unwrap().insert(handle, id);
        self.l2.set_device(handle, id);
        if let Some(d) = self.devices.lock().unwrap().get_mut(&id) {
            d.connected = true;
            d.state = DeviceState::Connected;
        }
        if le {
            self.smp.attach(handle, id);
            if let Err(e) = self.gatt.attach(handle, id) {
                eprintln!("[bt] att setup failed: {e}");
            }
        }
    }

    /// Connect the ACL link (if needed) and bring a profile up on top of it.
    pub fn connect_profile(&self, id: &DeviceId, kind: ProfileKind) -> Result<()> {
        let handle = self.connect_acl(id, Duration::from_secs(15))?;
        let le = id.address_type != AddressType::Bredr;
        // bonded devices expect an encrypted link before they serve anything
        self.ensure_encrypted(handle, true);
        self.profiles.connect(id, handle, le, kind)?;
        if let Some(i) = self.conns.lock().unwrap().get_mut(id) {
            if !i.profiles.contains(&kind) {
                i.profiles.push(kind);
            }
        }
        self.bonds.update_profiles(id, kind);
        self.bonds.touch_connected(id);
        if let Some(d) = self.devices.lock().unwrap().get_mut(id) {
            if !d.profiles.contains(&kind) {
                d.profiles.push(kind);
            }
        }
        self.bus.publish(Event::DeviceConnected { id: *id, profiles: vec![kind] });
        Ok(())
    }

    pub fn disconnect(&self, id: &DeviceId, reason: u8) -> Result<()> {
        let handle = {
            let mut c = self.conns.lock().unwrap();
            let i = c.get_mut(id).ok_or_else(|| Error::NotFound("no connection".into()))?;
            if i.state == ConnectionState::Connecting {
                return Err(Error::InvalidState("connection attempt in progress".into()));
            }
            i.state = ConnectionState::Disconnecting;
            i.handle
        };
        let waiter = self.hci.expect_event(move |e| e.code == ev::DISCONNECTION_COMPLETE && e.u16(1) == handle);
        let mut p = handle.to_le_bytes().to_vec();
        p.push(reason);
        if let Err(e) = self.hci.command_status(op::DISCONNECT, &p) {
            if let Some(i) = self.conns.lock().unwrap().get_mut(id) {
                i.state = ConnectionState::Connected;
            }
            return Err(e);
        }
        // the dispatch thread also cleans up on the event; both paths are idempotent
        let _ = waiter.wait(Duration::from_secs(5));
        self.cleanup(handle, format!("disconnected (reason 0x{reason:02x})"));
        Ok(())
    }

    /// Hang up every link politely (used when the adapter is switched off).
    pub fn disconnect_all(&self) {
        for c in self.list() {
            if c.state == ConnectionState::Connected {
                let _ = self.disconnect(&c.device, 0x15); // remote device powering off
            }
        }
    }

    fn cleanup(&self, handle: u16, reason: String) {
        let id = {
            // Whoever removes the handle owns the teardown. The connection entry goes in the same critical
            // section, so a caller that lost the race never observes a half-removed connection.
            let mut by_handle = self.by_handle.lock().unwrap();
            let Some(id) = by_handle.remove(&handle) else { return };
            self.conns.lock().unwrap().remove(&id);
            id
        };
        self.l2.cleanup_handle(handle); // notifies L2CAP channel consumers (HID etc.)
        let _ = self.profiles.disconnect(&id);
        self.smp.detach(handle);
        self.gatt.detach(handle);
        if let Some(d) = self.devices.lock().unwrap().get_mut(&id) {
            d.connected = false;
            d.state = DeviceState::Disconnected;
        }
        self.bus.publish(Event::DeviceDisconnected { id, reason });
    }

    /// Reconnect a trusted device with backoff.
    pub fn reconnect(&self, id: &DeviceId) -> Result<u16> {
        let mut delay = Duration::from_millis(500);
        for _ in 0..3 {
            if let Ok(h) = self.connect_acl(id, Duration::from_secs(10)) {
                return Ok(h);
            }
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
            ev::DISCONNECTION_COMPLETE if ev.u8(0) == 0 => {
                self.cleanup(ev.u16(1), format!("remote terminated (reason 0x{:02x})", ev.u8(3)));
            }
            ev::ENCRYPTION_CHANGE => {
                let (status, handle, enabled) = (ev.u8(0), ev.u16(1), ev.u8(3) != 0);
                let Some(id) = self.device_of(handle) else { return };
                if let Some(c) = self.conns.lock().unwrap().get_mut(&id) {
                    c.encrypted = status == 0 && enabled;
                }
                // LE encryption results are reported by the SMP layer; here only BR/EDR links
                if status != 0 && id.address_type == AddressType::Bredr {
                    self.bus.publish(Event::PairingComplete {
                        id,
                        success: false,
                        error: Some(format!("encryption failed: {}", hci_status_text(status))),
                    });
                }
            }
            ev::AUTHENTICATION_COMPLETE if ev.u8(0) == 0 => {
                // the link is authenticated (pairing finished, or the stored key was accepted): switch encryption on
                let handle = ev.u16(1);
                let Some(id) = self.device_of(handle) else { return };
                if id.address_type == AddressType::Bredr && !self.get(&id).is_some_and(|c| c.encrypted) {
                    let mut p = handle.to_le_bytes().to_vec();
                    p.push(0x01);
                    if let Err(e) = self.hci.command_status(op::SET_CONNECTION_ENCRYPTION, &p) {
                        eprintln!("[bt] enabling encryption failed: {e}");
                    }
                }
            }
            _ => {}
        }
    }

    /// Connection Request: bd_addr(6) class_of_device(3) link_type(1: 0 = SCO, 1 = ACL, 2 = eSCO)
    fn on_connection_request(&self, ev: &HciEvent) {
        let addr = ev.addr(0);
        let class = u32::from_le_bytes([ev.u8(6), ev.u8(7), ev.u8(8), 0]);
        if ev.u8(9) != 0x01 {
            // SCO/eSCO — the audio manager decides (requires an HFP/HSP session).
            if self.profiles.accept_sco(&addr) {
                return;
            }
            let mut p = addr.0.to_vec();
            p.push(0x0d); // rejected: limited resources
            let _ = self.hci.command_status(op::REJECT_SYNCHRONOUS_CONNECTION, &p);
            return;
        }
        let id = DeviceId { address: addr, address_type: AddressType::Bredr };
        if !self.accept_unbonded.load(Ordering::Relaxed) && !self.bonds.is_bonded(&id) {
            let mut p = addr.0.to_vec();
            p.push(0x0e); // rejected: security reasons
            let _ = self.hci.command_status(op::REJECT_CONNECTION_REQUEST, &p);
            return;
        }
        self.devices.lock().unwrap().entry(id).or_insert_with(|| {
            let mut d = Device::new(id);
            d.properties.class = DeviceClass(class);
            d
        });
        let mut p = addr.0.to_vec();
        p.push(0x00); // role: master
        let _ = self.hci.command_status(op::ACCEPT_CONNECTION_REQUEST, &p);
    }

    fn on_connection_complete(&self, ev: &HciEvent, le: bool) {
        let (status, handle, addr, addr_type) = if le {
            (ev.u8(1), ev.u16(2), ev.addr(6), if ev.u8(5) & 1 == 1 { AddressType::LeRandom } else { AddressType::LePublic })
        } else {
            (ev.u8(0), ev.u16(1), ev.addr(3), AddressType::Bredr)
        };
        if !le && ev.u8(9) != 0x01 {
            return; // SCO/eSCO links complete through Synchronous Connection Complete
        }
        if status != 0 {
            return; // outgoing failure: surfaced by connect_acl
        }
        if self.by_handle.lock().unwrap().contains_key(&handle) {
            return;
        }
        let id = DeviceId { address: addr, address_type: addr_type };
        // A connection we initiated is registered by connect_acl, which is waiting for this very event.
        if self.conns.lock().unwrap().contains_key(&id) {
            return;
        }
        // device-initiated (re)connection, e.g. a paired speaker powering on
        self.register(handle, id, le);
        self.ensure_encrypted(handle, false);
        let d = self.devices.lock().unwrap().get(&id).cloned();
        if let Some(d) = d {
            self.bus.publish(Event::DeviceUpdated { device: d });
        }
        self.bus.publish(Event::DeviceAclConnected { id });
    }
}
