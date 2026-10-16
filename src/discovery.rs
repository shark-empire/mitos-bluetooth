use crate::device::{now_ts, parse_eir, AddressType, Device, DeviceId, DeviceTable};
use crate::error::Result;
use crate::events::{Event, EventBus};
use crate::hci::{ev, op, HciClient, HciEvent};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Sender};
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
    /// Devices whose name still has to be asked for, served by one worker (one name request at a time).
    names: Sender<DeviceId>,
    name_queued: Arc<Mutex<HashSet<DeviceId>>>,
}

impl DiscoveryManager {
    pub fn new(hci: Arc<HciClient>, devices: Arc<DeviceTable>, bus: Arc<EventBus>, index: u32) -> Self {
        let (names, rx) = channel::<DeviceId>();
        let name_queued = Arc::new(Mutex::new(HashSet::new()));
        // The worker ends when the manager (the only Sender) is dropped.
        let (w_hci, w_devices, w_bus, w_queued) = (hci.clone(), devices.clone(), bus.clone(), name_queued.clone());
        std::thread::Builder::new()
            .name("bt-names".into())
            .spawn(move || {
                while let Ok(id) = rx.recv() {
                    resolve_name(&w_hci, &w_devices, &w_bus, id);
                    w_queued.lock().unwrap().remove(&id);
                }
            })
            .ok();
        DiscoveryManager {
            hci,
            devices,
            bus,
            index,
            st: Arc::new(Mutex::new(DiscoveryState::default())),
            janitor_running: AtomicBool::new(false),
            names,
            name_queued,
        }
    }

    pub fn is_active(&self) -> bool {
        self.st.lock().unwrap().active
    }

    /// Start BR/EDR inquiry and/or LE scan. Returns immediately; results arrive as events.
    pub fn start(&self, bredr: bool, le: bool, timeout_secs: u64) -> Result<()> {
        if bredr {
            let _ = self.hci.command(op::WRITE_INQUIRY_MODE, &[0x02]); // results with RSSI + EIR, where supported
            let mut p = Vec::new();
            p.extend_from_slice(&crate::hci::INQUIRY_LAP_GENERAL);
            p.push(timeout_secs.clamp(1, 48) as u8); // units of 1.28 s
            p.push(0x00); // unlimited responses
            self.hci.command_status(op::INQUIRY, &p)?;
        }
        if le {
            // active scan, 60 ms interval / 30 ms window, public own address, accept all
            let sp = [0x01, 0x60, 0x00, 0x30, 0x00, 0x00, 0x00];
            let _ = self.hci.command(op::LE_SET_SCAN_PARAMETERS, &sp);
            let _ = self.hci.command(op::LE_SET_SCAN_ENABLE, &[0x01, 0x00]);
        }
        {
            let mut st = self.st.lock().unwrap();
            st.active = true;
            st.le = le;
            st.until = Some(Instant::now() + Duration::from_secs(timeout_secs));
        }
        if !self.janitor_running.swap(true, Ordering::Relaxed) {
            self.spawn_janitor();
        }
        self.bus.publish(Event::DiscoveryStarted { index: self.index, le });
        Ok(())
    }

    fn spawn_janitor(&self) {
        let hci = self.hci.clone();
        let devices = self.devices.clone();
        let bus = self.bus.clone();
        let st = self.st.clone();
        let index = self.index;
        std::thread::Builder::new()
            .name("discovery-janitor".into())
            .spawn(move || loop {
                std::thread::sleep(Duration::from_secs(2));
                if !hci.is_running() {
                    break; // the adapter was switched off
                }
                // stop discovery when its deadline passes
                let expired = {
                    let mut s = st.lock().unwrap();
                    let due = s.active && s.until.is_some_and(|u| Instant::now() >= u);
                    if due {
                        s.active = false;
                        s.until = None;
                    }
                    due
                };
                if expired {
                    let _ = hci.command(op::INQUIRY_CANCEL, &[]);
                    let _ = hci.command(op::LE_SET_SCAN_ENABLE, &[0x00, 0x00]);
                    bus.publish(Event::DiscoveryStopped { index });
                }
                // age out devices that were neither seen for 60 s nor connected nor paired
                let now = now_ts();
                let mut lost = Vec::new();
                devices.lock().unwrap().retain(|id, d| {
                    let stale = now.saturating_sub(d.last_seen) > 60 && !d.connected && !d.paired;
                    if stale {
                        lost.push(*id);
                    }
                    !stale
                });
                for id in lost {
                    bus.publish(Event::DeviceLost { id });
                }
            })
            .ok();
    }

    pub fn stop(&self) -> Result<()> {
        // "command disallowed" just means nothing of that kind was running
        let _ = self.hci.command(op::INQUIRY_CANCEL, &[]);
        let _ = self.hci.command(op::LE_SET_SCAN_ENABLE, &[0x00, 0x00]);
        {
            let mut st = self.st.lock().unwrap();
            st.active = false;
            st.until = None;
        }
        self.bus.publish(Event::DiscoveryStopped { index: self.index });
        Ok(())
    }

    /// Called on the adapter dispatch thread for every HCI event.
    pub fn on_event(&self, ev: &HciEvent) {
        match ev.code {
            ev::INQUIRY_COMPLETE => {
                {
                    let mut st = self.st.lock().unwrap();
                    st.active = false;
                    st.until = None;
                }
                self.bus.publish(Event::DiscoveryStopped { index: self.index });
            }
            ev::INQUIRY_RESULT => self.on_result(ev, 0x02),
            ev::INQUIRY_RESULT_WITH_RSSI => self.on_result(ev, 0x22),
            ev::EXTENDED_INQUIRY_RESULT => self.on_result(ev, 0x2f),
            ev::LE_META_EVENT if ev.le_sub() == ev::LE_ADVERTISING_REPORT => self.on_le_adv(ev),
            _ => {}
        }
    }

    /// Inquiry result events: num_responses(1) then `num` fixed-size records (as every controller sends them).
    fn on_result(&self, ev: &HciEvent, kind: u8) {
        let record_len = match kind {
            0x02 => 14,
            0x22 => 14,
            _ => 254,
        };
        let n = usize::from(ev.u8(0));
        let mut off = 1;
        for _ in 0..n {
            if off + record_len > ev.params.len() {
                break;
            }
            let addr = ev.addr(off);
            let p = off + 6;
            let (class, rssi, eir) = match kind {
                0x02 => (u32::from_le_bytes([ev.u8(p + 3), ev.u8(p + 4), ev.u8(p + 5), 0]), 0, None),
                0x22 => (u32::from_le_bytes([ev.u8(p + 2), ev.u8(p + 3), ev.u8(p + 4), 0]), ev.u8(p + 7) as i8, None),
                _ => (
                    u32::from_le_bytes([ev.u8(p + 2), ev.u8(p + 3), ev.u8(p + 4), 0]),
                    ev.u8(p + 7) as i8,
                    Some(ev.bytes(p + 8, 240).to_vec()),
                ),
            };
            off += record_len;
            self.upsert(DeviceId { address: addr, address_type: AddressType::Bredr }, rssi, eir, class);
        }
    }

    /// LE Advertising Report: num_reports(1) then per report event_type(1) addr_type(1) addr(6) len(1) data(len) rssi(1).
    fn on_le_adv(&self, ev: &HciEvent) {
        let n = ev.u8(1);
        let mut off = 2;
        for _ in 0..n {
            if off + 10 > ev.params.len() {
                break;
            }
            off += 1; // event type
            let at = ev.u8(off);
            off += 1;
            let addr = ev.addr(off);
            off += 6;
            let dlen = usize::from(ev.u8(off));
            off += 1;
            let data = ev.bytes(off, dlen).to_vec();
            off += dlen;
            let rssi = ev.u8(off) as i8;
            off += 1;
            // address types 0x00/0x02 are public (0x02 = resolved to a public identity), 0x01/0x03 random
            let address_type = if at & 1 == 0 { AddressType::LePublic } else { AddressType::LeRandom };
            self.upsert(DeviceId { address: addr, address_type }, rssi, Some(data), 0);
        }
    }

    fn upsert(&self, id: DeviceId, rssi: i8, eir: Option<Vec<u8>>, class: u32) {
        let mut ad = parse_eir(&eir.unwrap_or_default());
        if ad.class_of_device == 0 {
            ad.class_of_device = class;
        }
        let mut devices = self.devices.lock().unwrap();
        let existed = devices.contains_key(&id);
        let changed = if existed {
            devices.get_mut(&id).is_some_and(|d| d.apply_ad(&ad, rssi))
        } else {
            let mut d = Device::new(id);
            d.apply_ad(&ad, rssi);
            devices.insert(id, d);
            true
        };
        if !changed {
            return;
        }
        let device = devices.get(&id).unwrap().clone();
        drop(devices);
        let nameless = device.properties.name.is_none();
        self.bus.publish(if existed { Event::DeviceUpdated { device } } else { Event::DeviceFound { device } });
        // BR/EDR devices that did not announce a name are asked for it, one at a time
        if nameless && id.address_type == AddressType::Bredr && self.name_queued.lock().unwrap().insert(id) {
            let _ = self.names.send(id);
        }
    }
}

/// Remote Name Request for one device; publishes DeviceUpdated when a name came back.
fn resolve_name(hci: &HciClient, devices: &DeviceTable, bus: &EventBus, id: DeviceId) {
    let target = id.address;
    let waiter = hci.expect_event(move |e| e.code == ev::REMOTE_NAME_REQUEST_COMPLETE && e.addr(1) == target);
    let mut p = target.0.to_vec();
    p.push(0x02); // page scan repetition mode R2
    p.push(0x00);
    p.extend_from_slice(&0u16.to_le_bytes()); // clock offset: unknown
    if hci.command_status(op::REMOTE_NAME_REQUEST, &p).is_err() {
        return;
    }
    let Ok(e) = waiter.wait(Duration::from_secs(8)) else { return };
    if e.u8(0) != 0 {
        return;
    }
    let raw: Vec<u8> = e.bytes(7, 248).iter().take_while(|&&c| c != 0).copied().collect();
    let name = String::from_utf8_lossy(&raw).trim().to_string();
    if name.is_empty() {
        return;
    }
    let updated = {
        let mut ds = devices.lock().unwrap();
        ds.get_mut(&id).map(|d| {
            d.properties.name = Some(name);
            d.clone()
        })
    };
    if let Some(device) = updated {
        bus.publish(Event::DeviceUpdated { device });
    }
}
