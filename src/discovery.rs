use crate::device::{parse_eir, now_ts, AddressType, Device, DeviceId, DeviceTable};
use crate::error::Result;
use crate::events::{Event, EventBus};
use crate::hci::{ev, op, HciClient, HciEvent};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Default, Clone, Copy)]
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
    pub st: Arc<Mutex<DiscoveryState>>,
    janitor_running: AtomicBool,
}

impl DiscoveryManager {
    pub fn new(hci: Arc<HciClient>, devices: Arc<DeviceTable>, bus: Arc<EventBus>, index: u32) -> Self {
        DiscoveryManager { hci, devices, bus, index, st: Arc::new(Mutex::new(DiscoveryState::default())), janitor_running: AtomicBool::new(false) }
    }

    pub fn is_active(&self) -> bool { self.st.lock().unwrap().active }

    /// Start BR/EDR inquiry and/or LE scan. Returns immediately; results arrive as events.
    pub fn start(&self, bredr: bool, le: bool, timeout_secs: u64) -> Result<()> {
        if bredr {
            self.hci.command(op::WRITE_INQUIRY_MODE, &[0x02])?;
            let mut p = Vec::new();
            p.extend_from_slice(&crate::hci::INQUIRY_LAP_GENERAL);
            p.push(timeout_secs.clamp(1, 48) as u8); // units of 1.28 s
            p.push(0x00); // unlimited responses
            self.hci.command_status(op::INQUIRY, &p)?;
        }
        if le {
            let sp = vec![0x01, 0x10, 0x00, 0x10, 0x00, 0x00, 0x00]; // active scan, 10 ms interval/window
            let _ = self.hci.command(op::LE_SET_SCAN_PARAMETERS, &sp);
            let _ = self.hci.command(op::LE_SET_SCAN_ENABLE, &[0x01, 0x00]);
        }
        {
            let mut st = self.st.lock().unwrap();
            st.active = true; st.le = le; st.until = Some(Instant::now() + Duration::from_secs(timeout_secs));
        }
        if !self.janitor_running.swap(true, Ordering::Relaxed) {
            let hci = self.hci.clone();
            let devices = self.devices.clone();
            let bus = self.bus.clone();
            let st = self.st.clone();
            let index = self.index;
            std::thread::Builder::new().name("discovery-janitor".into()).spawn(move || loop {
                std::thread::sleep(Duration::from_secs(2));
                // stop discovery when its deadline passes
                {
                    let mut s = st.lock().unwrap();
                    if s.active {
                        if let Some(u) = s.until {
                            if Instant::now() >= u {
                                let _ = hci.command(op::INQUIRY_CANCEL, &[]);
                                let _ = hci.command(op::LE_SET_SCAN_ENABLE, &[0x00, 0x00]);
                                s.active = false; s.until = None;
                                bus.publish(Event::DiscoveryStopped { index });
                            }
                        }
                    }
                }
                // age out devices not seen for 60 s
                let now = now_ts();
                let mut lost = Vec::new();
                devices.lock().unwrap().retain(|id, d| {
                    if now.saturating_sub(d.last_seen) > 60 && !d.connected { lost.push(*id); false } else { true }
                });
                for id in lost { bus.publish(Event::DeviceLost { id }); }
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

    /// Called on the adapter dispatch thread for every HCI event.
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
        // per-record: BD_ADDR(6) + PSRM(1) + Reserved(1 or 2) + CoD(3) + ClockOffset(2) [+ RSSI(1) for 0x22]
        let record_len = match kind { 0x02 => 14, 0x22 => 14, _ => 254 };
        let mut off = 1; // skip num_responses
        while off + record_len <= ev.params.len() {
            let addr = ev.addr(off);
            let p = off + 6;
            let (class, rssi, eir) = match kind {
                0x02 => { // BD_ADDR, PSRM, PSPM, PSM, CoD, clock
                    let c = u32::from_le_bytes([ev.u8(p + 3), ev.u8(p + 4), ev.u8(p + 5), 0]);
                    (c, 0i8, None)
                }
                0x22 => { // BD_ADDR, PSRM, reserved, CoD, clock, RSSI
                    let c = u32::from_le_bytes([ev.u8(p + 2), ev.u8(p + 3), ev.u8(p + 4), 0]);
                    (c, ev.u8(p + 7) as i8, None)
                }
                _ => { // extended: same as above + RSSI + 240 bytes of EIR
                    let c = u32::from_le_bytes([ev.u8(p + 2), ev.u8(p + 3), ev.u8(p + 4), 0]);
                    (c, ev.u8(p + 7) as i8, Some(ev.bytes(p + 8, 240).to_vec()))
                }
            };
            off += record_len;
            self.upsert(DeviceId { address: addr, address_type: AddressType::Bredr }, rssi, eir, class);
        }
    }

    fn on_le_adv(&self, ev: &HciEvent) {
        let n = ev.u8(1);
        let mut off = 2;
        for _ in 0..n {
            if off + 10 > ev.params.len() { break; }
            off += 1; // event type
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
        let mut ad = parse_eir(&eir.unwrap_or_default());
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
            // resolve missing BR/EDR names in the background
            if id.address_type == AddressType::Bredr && self.devices.lock().unwrap().get(&id).and_then(|d| d.properties.name.clone()).is_none() {
                let hci = self.hci.clone(); let devices = self.devices.clone(); let bus = self.bus.clone();
                std::thread::spawn(move || {
                    let mut p = id.address.0.to_vec();
                    p.push(0x02); // page scan repetition mode R2
                    p.push(0x00);
                    p.extend_from_slice(&0u16.to_le_bytes());
                    if hci.command_status(op::REMOTE_NAME_REQUEST, &p).is_ok() {
                        if let Ok(e) = hci.wait_event(
                            move |e| e.code == ev::REMOTE_NAME_REQUEST_COMPLETE && e.addr(1) == id.address,
                            Duration::from_secs(8))
                        {
                            if e.u8(0) == 0 {
                                let name: Vec<u8> = e.bytes(7, 248).iter().take_while(|&&c| c != 0).cloned().collect();
                                let name = String::from_utf8_lossy(&name).trim().to_string();
                                if !name.is_empty() {
                                    let mut ds = devices.lock().unwrap();
                                    if let Some(d) = ds.get_mut(&id) { d.properties.name = Some(name); }
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
