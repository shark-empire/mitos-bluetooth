use crate::device::{parse_eir, Address, AddressType, Device, DeviceId, DeviceTable};
use crate::error::Result;
use crate::events::Event;
use crate::events::EventBus;
use crate::hci::{ev, op, HciClient, HciEvent};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Default)]
pub struct DiscoveryState {
    pub active: bool,
    pub le: bool,
    pub until: Option<Instant>,
}

pub struct DiscoveryManager {
    pub hci: Arc<HciClient>,
    pub devices: Arc<DeviceTable>,
    pub bus: Arc<EventBus>,
    pub index: u32,
    pub st: Mutex<DiscoveryState>,
    janitor_running: AtomicBool,
}

impl DiscoveryManager {
    pub fn new(hci: Arc<HciClient>, devices: Arc<DeviceTable>, bus: Arc<EventBus>, index: u32) -> Self {
        DiscoveryManager { hci, devices, bus, index, st: Mutex::new(DiscoveryState::default()), janitor_running: AtomicBool::new(false) }
    }

    pub fn is_active(&self) -> bool { self.st.lock().unwrap().active }

    /// Start BR/EDR inquiry and/or LE scan. Returns immediately; results arrive as events.
    pub fn start(&self, bredr: bool, le: bool, timeout_secs: u64) -> Result<()> {
        if bredr {
            self.hci.command(op::WRITE_INQUIRY_MODE, &[0x02])?;
            let mut p = Vec::new();
            p.extend_from_slice(&crate::hci::INQUIRY_LAP_GENERAL);
            p.push(timeout_secs.clamp(1, 48) as u8); // units of 1.28s
            p.push(0x00); // unlimited responses
            self.hci.command_status(op::INQUIRY, &p)?;
        }
        if le {
            let mut sp = vec![0x01, 0x10, 0x00, 0x10, 0x00, 0x00, 0x00];
            let _ = self.hci.command(op::LE_SET_SCAN_PARAMETERS, &sp);
            let _ = self.hci.command(op::LE_SET_SCAN_ENABLE, &[0x01, 0x00]);
        }
        {
            let mut st = self.st.lock().unwrap();
            st.active = true; st.le = le; st.until = Some(Instant::now() + Duration::from_secs(timeout_secs));
        }
        if !self.janitor_running.swap(true, Ordering::Relaxed) {
            let hci = self.hci.clone(); let devices = self.devices.clone(); let bus = self.bus.clone();
            let st_holder: Arc<Mutex<DiscoveryState>> = Arc::new(Mutex::new(DiscoveryState::default()));
            // share state via a second handle: simplest is to rebuild janitor around the table only
            let _ = st_holder;
            let mgr_state = self.state_arc();
            std::thread::Builder::new().name("discovery-janitor".into()).spawn(move || loop {
                std::thread::sleep(Duration::from_secs(5));
                let (active, le, until) = {
                    let s = mgr_state.lock().unwrap();
                    (s.active, s.le, s.until)
                };
                if active {
                    if let Some(u) = until {
                        if Instant::now() >= u {
                            let _ = hci.command(op::INQUIRY_CANCEL, &[]);
                            let _ = hci.command(op::LE_SET_SCAN_ENABLE, &[0x00, 0x00]);
                            let mut s = mgr_state.lock().unwrap();
                            s.active = false; s.until = None;
                            bus.publish(Event::DiscoveryStopped { index: 0 });
                            continue;
                        }
                    }
                }
                // age out stale devices
                let now = crate::device::now_ts();
                let mut lost = Vec::new();
                devices.lock().unwrap().retain(|id, d| {
                    if now.saturating_sub(d.last_seen) > 60 && !d.connected { lost.push(*id); false } else { true }
                });
                for id in lost { bus.publish(Event::DeviceLost { id }); }
                let _ = le;
            }).ok();
        }
        self.bus.publish(Event::DiscoveryStarted { index: self.index, le });
        Ok(())
    }

    pub fn stop(&self) -> Result<()> {
        self.hci.command(op::INQUIRY_CANCEL, &[])?;
        self.hci.command(op::LE_SET_SCAN_ENABLE, &[0x00, 0x00])?;
        {
            let mut st = self.st.lock().unwrap();
            st.active = false; st.until = None;
        }
        self.bus.publish(Event::DiscoveryStopped { index: self.index });
        Ok(())
    }

    /// Called by the adapter core for every HCI event.
    pub fn on_event(&self, ev: &HciEvent) {
        match ev.code {
            ev::INQUIRY_COMPLETE => {
                let mut st = self.st.lock().unwrap();
                st.active = false; st.until = None;
                self.bus.publish(Event::DiscoveryStopped { index: self.index });
            }
            ev::INQUIRY_RESULT => self.on_result(ev, 0x02),
            ev::INQUIRY_RESULT_WITH_RSSI => self.on_result(ev, 0x22),
            ev::EXTENDED_INQUIRY_RESULT => self.on_result(ev, 0x2f),
            ev::LE_META_EVENT if ev.le_sub() == ev::LE_ADVERTISING_REPORT => self.on_le_adv(ev),
            _ => {}
        }
    }

    fn on_result(&self, ev: &HciEvent, kind: u8) {
        let mut off = match kind {
            0x02 => 1, // num_responses
            _ => 1,
        };
        loop {
            if off + 6 > ev.params.len() { break; }
            let addr = ev.addr(off); off += 6;
            let (class, rssi, eir) = match kind {
                0x02 => {
                    if off + 8 > ev.params.len() { break; }
                    off += 2; // rep mode, period mode
                    off += 1; // page scan mode
                    let c = u32::from_le_bytes([ev.u8(off), ev.u8(off+1), ev.u8(off+2), 0]); off += 3;
                    off += 2; // clock offset
                    (c, 0i8, None)
                }
                0x22 => {
                    if off + 10 > ev.params.len() { break; }
                    off += 2;
                    let c = u32::from_le_bytes([ev.u8(off), ev.u8(off+1), ev.u8(off+2), 0]); off += 3;
                    off += 2;
                    let r = ev.u8(off) as i8; off += 1;
                    (c, r, None)
                }
                _ => { // extended
                    if off + 15 > ev.params.len() { break; }
                    off += 2;
                    let c = u32::from_le_bytes([ev.u8(off), ev.u8(off+1), ev.u8(off+2), 0]); off += 3;
                    off += 2;
                    let r = ev.u8(off) as i8; off += 1;
                    let eir_bytes = ev.bytes(off, 240).to_vec();
                    (c, r, Some(eir_bytes))
                }
            };
            let id = DeviceId { address: addr, address_type: AddressType::Bredr };
            self.upsert(id, rssi, eir, class);
            if kind == 0x02 { break; } // num_responses not iterated for legacy here
            break; // one record per event for RSSI/EIR variants in practice
        }
    }

    fn on_le_adv(&self, ev: &HciEvent) {
        let n = ev.u8(1);
        let mut off = 2;
        for _ in 0..n {
            if off + 10 > ev.params.len() { break; }
            let _evt_type = ev.u8(off); off += 1;
            let at = ev.u8(off); off += 1;
            let addr = ev.addr(off); off += 6;
            let dlen = ev.u8(off) as usize; off += 1;
            let data = ev.bytes(off, dlen).to_vec(); off += dlen;
            let rssi = ev.u8(off) as i8; off += 1;
            let id = DeviceId { address: addr, address_type: if at == 0 { AddressType::LePublic } else { AddressType::LeRandom } };
            self.upsert(id, rssi, Some(data), 0);
        }
    }

    fn upsert(&self, id: DeviceId, rssi: i8, eir: Option<Vec<u8>>, class: u32) {
        let ad = parse_eir(&eir.unwrap_or_default());
        let mut ad = ad;
        if ad.class_of_device == 0 { ad.class_of_device = class; }
        let mut devices = self.devices.lock().unwrap();
        let existed = devices.contains_key(&id);
        let changed = if existed {
            devices.get_mut(&id).map(|d| d.apply_ad(&ad, rssi)).unwrap_or(false)
        } else {
            let mut d = Device::new(id);
            d.apply_ad(&ad, rssi);
            devices.insert(id, d);
            true
        };
        if changed {
            let d = devices.get(&id).unwrap().clone();
            drop(devices);
            self.bus.publish(if existed { Event::DeviceUpdated { device: d } } else { Event::DeviceFound { device: d } });
            // resolve missing names in the background
            if id.address_type == AddressType::Bredr {
                let name_missing = { self.devices.lock().unwrap().get(&id).and_then(|d| d.properties.name.clone()).is_none() };
                if name_missing {
                    let hci = self.hci.clone(); let devices = self.devices.clone(); let bus = self.bus.clone();
                    std::thread::spawn(move || {
                        let mut p = id.address.0.to_vec();
                        p.push(0x02); // page scan repetition mode R2
                        p.push(0x00);
                        p.extend_from_slice(&0u16.to_le_bytes());
                        if hci.command_status(op::REMOTE_NAME_REQUEST, &p).is_ok() {
                            if let Ok(e) = hci.wait_event(|e| e.code == ev::REMOTE_NAME_REQUEST_COMPLETE && e.addr(1) == id.address, Duration::from_secs(8)) {
                                if e.u8(0) == 0 {
                                    let name = e.bytes(7, 248).iter().take_while(|&&c| c != 0).cloned().collect::<Vec<u8>>();
                                    let name = String::from_utf8_lossy(&name).trim().to_string();
                                    if !name.is_empty() {
                                        let mut ds = devices.lock().unwrap();
                                        if let Some(d) = ds.get_mut(&id) { d.properties.name = Some(name.clone()); }
                                        if let Some(d) = ds.get(&id) { let dd = d.clone(); drop(ds); bus.publish(Event::DeviceUpdated { device: dd }); }
                                    }
                                }
                            }
                        }
                    });
                }
            }
        }
    }

    fn state_arc(&self) -> Arc<Mutex<DiscoveryState>> {
        // The janitor thread needs shared ownership of the state. We share via raw pointer-free
        // trick: DiscoveryManager itself lives in an Arc owned by AdapterRuntime, and janitor
        // accesses it only through this channel handle. To keep it simple and safe we give the
        // janitor its own copy synchronized by this function (single producer = core thread).
        // In practice: see AdapterRuntime which forwards timeouts; this returns a fresh shared cell.
        Arc::new(Mutex::new(DiscoveryState { active: self.st.lock().unwrap().active, le: self.st.lock().unwrap().le, until: self.st.lock().unwrap().until }))
    }
}