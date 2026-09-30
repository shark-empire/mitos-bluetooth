use crate::device::{DeviceId, DeviceState, DeviceTable};
use crate::error::{Error, Result};
use crate::events::{Event, EventBus, HidInput};
use crate::gatt::{GattCharacteristic, GattManager};
use crate::l2cap::{L2cap, PSM_HID_CONTROL, PSM_HID_INTERRUPT};
use crate::profile::ProfileKind;
use crate::sdp::SdpClient;
use serde_json::json;
use std::collections::HashMap;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};

const HID_SVC: u16 = 0x1124;        // SDP: classic HID service
const HOGP_SVC: u16 = 0x1812;       // GATT: HID over GATT service
const UUID_REPORT_MAP: u16 = 0x2a4b;
const UUID_REPORT: u16 = 0x2a4d;
const UUID_CONTROL_POINT: u16 = 0x2a4c;
const UUID_PROTOCOL_MODE: u16 = 0x2a4e;
const UUID_REPORT_REF: u16 = 0x2908;
const UUID_BOOT_KBD_IN: u16 = 0x2a22;
const UUID_BOOT_MOUSE_IN: u16 = 0x2a33;
const HIDP_SET_PROTOCOL: u8 = 0x70; // |1 => report protocol
const HIDP_SET_REPORT_OUT: u8 = 0x52;

// ===================== HID report descriptor parsing =====================

#[derive(Clone, Debug, Default)]
pub struct HidField {
    pub usage_page: u16,
    pub usages: Vec<u16>,
    pub usage_min: Option<u16>,
    pub usage_max: Option<u16>,
    pub report_size: u16,
    pub report_count: u16,
    pub logical_min: i32,
    pub logical_max: i32,
    pub kind: u8,   // 0 input, 1 output, 2 feature
    pub flags: u8,  // main-item data: bit0 const, bit1 variable, bit2 relative
}

#[derive(Clone, Debug, Default)]
pub struct ReportFormat {
    pub report_id: Option<u8>,
    pub kind: u8,
    pub fields: Vec<HidField>,
}

fn push_field(out: &mut Vec<ReportFormat>, rid: Option<u8>, kind: u8, f: HidField) {
    if let Some(fmt) = out.iter_mut().find(|x| x.report_id == rid && x.kind == kind) {
        fmt.fields.push(f);
    } else {
        out.push(ReportFormat { report_id: rid, kind, fields: vec![f] });
    }
}

/// Parse a HID report descriptor into report formats (input/output/feature per report id).
pub fn parse_descriptor(d: &[u8]) -> Vec<ReportFormat> {
    let mut out: Vec<ReportFormat> = Vec::new();
    let mut page: u16 = 0;
    let mut size: u16 = 0;
    let mut count: u16 = 0;
    let mut lmin: i32 = 0;
    let mut lmax: i32 = 0;
    let mut rid: Option<u8> = None;
    let mut umin: Option<u16> = None;
    let mut umax: Option<u16> = None;
    let mut usages: Vec<u16> = Vec::new();
    let mut i = 0;
    while i < d.len() {
        let item = d[i]; i += 1;
        let n = match item & 0x03 { 0 => 0, 1 => 1, 2 => 2, _ => 4 } as usize;
        if i + n > d.len() { break; }
        let raw: u32 = match n {
            0 => 0,
            1 => d[i] as u32,
            2 => u16::from_le_bytes([d[i], d[i + 1]]) as u32,
            _ => u32::from_le_bytes(d[i..i + 4].try_into().unwrap()),
        };
        let sval: i32 = if n > 0 && (raw >> (n * 8 - 1)) & 1 == 1 {
            (raw as i64 - (1i64 << (n * 8))) as i32
        } else { raw as i32 };
        i += n;
        match item & 0xFC {
            0x04 | 0x05 | 0x06 | 0x07 => page = (raw & 0xffff) as u16,   // Usage Page
            0x14 => lmin = sval,                                          // Logical Minimum
            0x24 => lmax = sval,                                          // Logical Maximum
            0x74 => size = raw as u16,                                    // Report Size
            0x84 => rid = Some(raw as u8),                                // Report ID
            0x94 => count = raw as u16,                                   // Report Count
            0x08 => {                                                     // Usage (local)
                if n == 4 { page = (raw >> 16) as u16; usages.push((raw & 0xffff) as u16); }
                else { usages.push(raw as u16); }
            }
            0x18 => umin = Some(raw as u16),                              // Usage Minimum
            0x28 => umax = Some(raw as u16),                              // Usage Maximum
            0x80 | 0x90 | 0xB0 => {                                       // Input / Output / Feature
                let kind = match item & 0xFC { 0x80 => 0, 0x90 => 1, _ => 2 };
                let f = HidField {
                    usage_page: page, usages: std::mem::take(&mut usages),
                    usage_min: umin.take(), usage_max: umax.take(),
                    report_size: size, report_count: count,
                    logical_min: lmin, logical_max: lmax,
                    kind, flags: raw as u8,
                };
                push_field(&mut out, rid, kind, f);
            }
            0xA0 | 0xC0 => { usages.clear(); umin = None; umax = None; }  // (End) Collection clears locals
            _ => {}                                                       // physical/unit/push/pop ignored
        }
    }
    out
}

// ===================== report decoding =====================

pub struct RawEvent { page: u16, usage: u16, value: i32, variable: bool, lmin: i32, lmax: i32 }

fn extract_bits(data: &[u8], bit_off: usize, bits: usize) -> u64 {
    let mut v = 0u64;
    for b in 0..bits.min(64) {
        let idx = bit_off + b;
        let byte = idx / 8;
        if byte >= data.len() { break; }
        if data[byte] & (1 << (idx % 8)) != 0 { v |= 1 << b; }
    }
    v
}
fn sign_extend(v: u64, bits: usize) -> i64 {
    if bits == 0 || bits >= 64 { return v as i64; }
    let shift = 64 - bits;
    ((v << shift) as i64) >> shift
}

fn decode_fields(fmts: &[&ReportFormat], data: &[u8]) -> Vec<RawEvent> {
    let mut out = Vec::new();
    let mut off = 0usize;
    for f in fmts {
        for field in &f.fields {
            let bits = field.report_size as usize;
            let cnt = field.report_count as usize;
            if bits == 0 || cnt == 0 { continue; }
            let constant = field.flags & 0x01 != 0;
            let variable = field.flags & 0x02 != 0;
            for k in 0..cnt {
                let raw = extract_bits(data, off, bits);
                let v = if field.logical_min < 0 { sign_extend(raw, bits) } else { raw as i64 };
                off += bits;
                if constant { continue; }
                if variable {
                    let usage = field.usages.get(k).copied()
                        .or_else(|| field.usage_min.map(|m| m.wrapping_add(k as u16)))
                        .unwrap_or(0);
                    out.push(RawEvent { page: field.usage_page, usage, value: v as i32, variable, lmin: field.logical_min, lmax: field.logical_max });
                } else if v != 0 {
                    // array field: the value IS a usage id (keyboard keys, hat switches)
                    out.push(RawEvent { page: field.usage_page, usage: v as u16, value: 1, variable: false, lmin: field.logical_min, lmax: field.logical_max });
                }
            }
        }
    }
    out
}

fn is_axis(u: u16) -> bool { matches!(u, 0x30..=0x39) }

/// Turn decoded field values into a typed input event.
pub fn interpret(events: &[RawEvent]) -> HidInput {
    if events.iter().any(|e| e.page == 0x07) { // Keyboard/Keypad page
        let mut modifiers = 0u8;
        let mut keys = Vec::new();
        for e in events {
            if e.page != 0x07 { continue; }
            if e.variable {
                if (0xE0..=0xE7).contains(&e.usage) && e.value != 0 { modifiers |= 1 << (e.usage - 0xE0); }
            } else if e.usage != 0 { keys.push(e.usage as u8); }
        }
        return HidInput::Keyboard { modifiers, keys };
    }
    let buttons: Vec<u16> = events.iter().filter(|e| e.page == 0x09 && e.value != 0).map(|e| e.usage).collect();
    let axes: Vec<&RawEvent> = events.iter().filter(|e| e.page == 0x01 && e.variable && is_axis(e.usage)).collect();
    if buttons.is_empty() && axes.is_empty() { return HidInput::Raw(Vec::new()); }
    let has_xy = axes.iter().any(|e| e.usage == 0x30 || e.usage == 0x31);
    if has_xy && buttons.len() <= 3 {
        let mut b = 0u8;
        for u in &buttons { if (1..=8).contains(u) { b |= 1 << (u - 1); } }
        return HidInput::Mouse {
            buttons: b,
            dx: axes.iter().find(|e| e.usage == 0x30).map(|e| e.value).unwrap_or(0),
            dy: axes.iter().find(|e| e.usage == 0x31).map(|e| e.value).unwrap_or(0),
            wheel: axes.iter().find(|e| e.usage == 0x38).map(|e| e.value).unwrap_or(0),
        };
    }
    // gamepad: normalize axes from [logical_min..logical_max] to [-32767..32767]
    let mut b = 0u32;
    for u in &buttons { if (1..=32).contains(u) { b |= 1 << (u - 1); } }
    let axes: Vec<(u8, i32)> = axes.iter().map(|e| {
        let norm = if e.lmax > e.lmin {
            ((e.value - e.lmin) as i64 * 65534 / (e.lmax - e.lmin) as i64 - 32767) as i32
        } else { e.value };
        (e.usage as u8, norm)
    }).collect();
    HidInput::Gamepad { buttons: b, axes }
}

/// Decode a report-protocol report (handles the leading report-id byte).
pub fn decode_report(formats: &[ReportFormat], value: &[u8]) -> HidInput {
    let has_ids = formats.iter().any(|f| f.kind == 0 && f.report_id.is_some());
    if has_ids && !value.is_empty() {
        let id = value[0];
        let fmts: Vec<&ReportFormat> = formats.iter().filter(|f| f.kind == 0 && f.report_id == Some(id)).collect();
        if fmts.is_empty() { return HidInput::Raw(value.to_vec()); }
        interpret(&decode_fields(&fmts, &value[1..]))
    } else {
        let fmts: Vec<&ReportFormat> = formats.iter().filter(|f| f.kind == 0 && f.report_id.is_none()).collect();
        if fmts.is_empty() { return HidInput::Raw(value.to_vec()); }
        interpret(&decode_fields(&fmts, value))
    }
}

/// Decode a boot-protocol report (fixed layouts).
pub fn decode_boot_data(data: &[u8], mouse: bool) -> HidInput {
    if mouse {
        HidInput::Mouse {
            buttons: data.first().copied().unwrap_or(0),
            dx: data.get(1).copied().unwrap_or(0) as i8 as i32,
            dy: data.get(2).copied().unwrap_or(0) as i8 as i32,
            wheel: data.get(3).copied().unwrap_or(0) as i8 as i32,
        }
    } else {
        HidInput::Keyboard {
            modifiers: data.first().copied().unwrap_or(0),
            keys: data.iter().skip(2).take(6).filter(|&&k| k != 0).cloned().collect(),
        }
    }
}

// ===================== HID host =====================

#[derive(Clone)]
enum HidTransport { Classic { control: u16, interrupt: u16 }, Le }

#[derive(Clone)]
struct HidSession {
    conn_handle: u16,
    transport: HidTransport,
    boot: bool,                            // boot protocol (no descriptor)
    formats: Vec<ReportFormat>,            // report protocol (parsed descriptor)
    le_reports: HashMap<u16, u8>,          // GATT: value handle -> report id
    le_boot_kind: Option<u8>,              // GATT boot: 0 keyboard, 1 mouse
}

pub struct HidHost {
    pub l2: Arc<L2cap>,
    pub gatt: Arc<GattManager>,
    pub devices: Arc<DeviceTable>,
    pub bus: Arc<EventBus>,
    st: Mutex<HashMap<DeviceId, HidSession>>,
    input_sock: Mutex<Option<UnixStream>>,
}

impl HidHost {
    pub fn new(l2: Arc<L2cap>, gatt: Arc<GattManager>, devices: Arc<DeviceTable>, bus: Arc<EventBus>) -> Arc<Self> {
        let host = Arc::new(HidHost { l2, gatt, devices, bus, st: Mutex::new(HashMap::new()), input_sock: Mutex::new(None) });
        // Listen for device-initiated channels (a paired keyboard reconnecting).
        let (tx11, rx11) = channel();
        let (tx13, rx13) = channel();
        host.l2.register_listener(PSM_HID_CONTROL, tx11);
        host.l2.register_listener(PSM_HID_INTERRUPT, tx13);
        for (rx, is_control) in [(rx11, true), (rx13, false)] {
            let h = host.clone();
            std::thread::spawn(move || {
                while let Ok(p) = rx.recv() {
                    if p.closed { continue; }
                    h.on_inbound_channel(p.handle, p.cid, is_control);
                }
            });
        }
        // GATT notifications -> HID reports (HOGP)
        let h = host.clone();
        let evrx = host.bus.subscribe();
        std::thread::spawn(move || {
            while let Ok(ev) = evrx.recv() {
                if let Event::GattNotification { id, attribute, value } = ev {
                    h.on_gatt_report(&id, attribute, &value);
                }
            }
        });
        host
    }

    pub fn connect(self: &Arc<Self>, device: &DeviceId, handle: u16, le: bool) -> Result<()> {
        if le { self.connect_le(device, handle) } else { self.connect_classic(device, handle) }
    }

    pub fn disconnect(&self, device: &DeviceId) -> Result<()> {
        if let Some(s) = self.st.lock().unwrap().remove(device) {
            if let HidTransport::Classic { control, interrupt } = s.transport {
                let _ = self.l2.disconnect(control);
                let _ = self.l2.disconnect(interrupt);
            }
        }
        Ok(())
    }

    // ---- classic (BR/EDR) ----

    fn connect_classic(self: &Arc<Self>, device: &DeviceId, handle: u16) -> Result<()> {
        // 1. SDP: find the HID service (PSM + optional report descriptor)
        let (psm_ctrl, descriptor) = match SdpClient::connect(self.l2.clone(), handle) {
            Ok(mut sdp) => match sdp.query(HID_SVC) {
                Ok(svc) => (svc.psm.unwrap_or(PSM_HID_CONTROL), svc.hid_descriptor),
                Err(_) => (PSM_HID_CONTROL, None),
            },
            Err(_) => (PSM_HID_CONTROL, None),
        };
        // 2. L2CAP channels (control first, then interrupt — per HID spec)
        let control = self.l2.connect(handle, psm_ctrl)?;
        let interrupt = match self.l2.connect(handle, PSM_HID_INTERRUPT) {
            Ok(i) => i,
            Err(e) => { let _ = self.l2.disconnect(control); return Err(e); }
        };
        let formats = descriptor.as_deref().map(parse_descriptor).unwrap_or_default();
        let boot = formats.is_empty();
        // 3. session + channel pumps
        self.st.lock().unwrap().insert(*device, HidSession {
            conn_handle: handle,
            transport: HidTransport::Classic { control, interrupt },
            boot, formats,
            le_reports: HashMap::new(), le_boot_kind: None,
        });
        self.attach_channel(device, control, true)?;
        self.attach_channel(device, interrupt, false)?;
        // 4. protocol: report mode when we have the descriptor, boot mode otherwise
        let _ = self.l2.send(control, &[HIDP_SET_PROTOCOL | if boot { 0 } else { 1 }]);
        Ok(())
    }

    fn attach_channel(self: &Arc<Self>, device: &DeviceId, cid: u16, is_control: bool) -> Result<()> {
        let (tx, rx) = channel();
        self.l2.register_handler(cid, tx);
        let h = self.clone();
        let dev = *device;
        std::thread::spawn(move || {
            while let Ok(p) = rx.recv() {
                if p.closed { break; }
                h.on_channel_data(&dev, is_control, &p.data);
            }
            h.st.lock().unwrap().remove(&dev);
        });
        Ok(())
    }

    fn on_inbound_channel(self: &Arc<Self>, handle: u16, cid: u16, is_control: bool) {
        let Some(device) = self.l2.device(handle) else { return; };
        {
            let mut st = self.st.lock().unwrap();
            let s = st.entry(device).or_insert_with(|| HidSession {
                conn_handle: handle,
                transport: HidTransport::Classic { control: 0, interrupt: 0 },
                boot: true, formats: Vec::new(),
                le_reports: HashMap::new(), le_boot_kind: None,
            });
            if let HidTransport::Classic { control, interrupt } = &mut s.transport {
                if is_control { *control = cid; } else { *interrupt = cid; }
            }
        }
        self.attach_channel(&device, cid, is_control).ok();
        {
            let mut ds = self.devices.lock().unwrap();
            if let Some(d) = ds.get_mut(&device) {
                d.connected = true;
                d.state = DeviceState::Connected;
                if !d.profiles.contains(&ProfileKind::Hid) { d.profiles.push(ProfileKind::Hid); }
            }
        }
        if !is_control {
            self.bus.publish(Event::DeviceConnected { id: device, profiles: vec![ProfileKind::Hid] });
        }
    }

    fn on_channel_data(&self, device: &DeviceId, is_control: bool, data: &[u8]) {
        let Some(&hdr) = data.first() else { return };
        if hdr & 0xF0 == 0xA0 {          // DATA frame
            if hdr & 0x0F == 1 { self.on_report(device, &data[1..]); } // input report
        } else if hdr < 0x40 {           // HANDSHAKE (response on control channel)
            if is_control && hdr != 0x00 { eprintln!("[hid] handshake error 0x{hdr:02x}"); }
        }
        // HID_CONTROL / GET_* responses are not needed
    }

    fn on_report(&self, device: &DeviceId, payload: &[u8]) {
        let Some(s) = self.st.lock().unwrap().get(device).cloned() else { return };
        let input = if s.boot || s.formats.is_empty() {
            let mouse = self.devices.lock().unwrap().get(device)
                .map(|d| d.properties.class.is_pointing()).unwrap_or(false);
            decode_boot_data(payload, mouse)
        } else {
            decode_report(&s.formats, payload)
        };
        self.forward(device, &input);
        self.bus.publish(Event::HidReport { id: *device, input });
    }

    // ---- LE (HID over GATT / HOGP) ----

    fn connect_le(self: &Arc<Self>, device: &DeviceId, handle: u16) -> Result<()> {
        let services = self.gatt.discover_services(handle)?;
        let hogp = services.iter().find(|s| s.uuid.as16() == Some(HOGP_SVC))
            .ok_or_else(|| Error::NotSupported("no HID-over-GATT service on this LE device".into()))?;
        let chars = self.gatt.discover_characteristics(handle, hogp)?;
        let formats = match chars.iter().find(|c| c.uuid.as16() == Some(UUID_REPORT_MAP)) {
            Some(c) => self.gatt.read(handle, c.value_handle).map(|d| parse_descriptor(&d)).unwrap_or_default(),
            None => Vec::new(),
        };
        let boot = formats.is_empty();
        let mut le_reports: HashMap<u16, u8> = HashMap::new();
        let mut le_boot_kind = None;
        let mut have_any = !formats.is_empty();
        for c in &chars {
            match c.uuid.as16() {
                Some(UUID_REPORT) => {
                    // Report Reference descriptor: [report id, report type (1=input)]
                    let (rid, rtype) = c.descriptors.iter()
                        .find(|d| d.uuid.as16() == Some(UUID_REPORT_REF))
                        .and_then(|d| self.gatt.read(handle, d.handle).ok())
                        .map(|v| (v.first().copied().unwrap_or(0), v.get(1).copied().unwrap_or(1)))
                        .unwrap_or((0, 1));
                    if rtype == 1 {
                        let _ = self.gatt.subscribe(handle, c.value_handle, 1);
                        le_reports.insert(c.value_handle, rid);
                        have_any = true;
                    }
                }
                Some(UUID_BOOT_KBD_IN) => {
                    let _ = self.gatt.subscribe(handle, c.value_handle, 1);
                    le_reports.insert(c.value_handle, 0);
                    le_boot_kind = Some(0);
                    have_any = true;
                }
                Some(UUID_BOOT_MOUSE_IN) => {
                    let _ = self.gatt.subscribe(handle, c.value_handle, 1);
                    le_reports.insert(c.value_handle, 0);
                    le_boot_kind = Some(1);
                    have_any = true;
                }
                Some(UUID_PROTOCOL_MODE) if !boot => {
                    let _ = self.write_char(handle, c, &[0x01]); // report mode
                }
                Some(UUID_CONTROL_POINT) => {
                    let _ = self.write_char(handle, c, &[0x00]); // exit suspend
                }
                _ => {}
            }
        }
        if !have_any {
            return Err(Error::NotSupported("HID service has no usable input reports".into()));
        }
        self.st.lock().unwrap().insert(*device, HidSession {
            conn_handle: handle, transport: HidTransport::Le,
            boot, formats, le_reports, le_boot_kind,
        });
        Ok(())
    }

    fn write_char(&self, handle: u16, c: &GattCharacteristic, data: &[u8]) -> Result<()> {
        if c.properties & 0x04 != 0 { self.gatt.write(handle, c.value_handle, data, false) }
        else if c.properties & 0x08 != 0 { self.gatt.write(handle, c.value_handle, data, true) }
        else { Err(Error::NotSupported("characteristic not writable".into())) }
    }

    fn on_gatt_report(&self, device: &DeviceId, attr: u16, value: &[u8]) {
        let Some(s) = self.st.lock().unwrap().get(device).cloned() else { return };
        if !matches!(s.transport, HidTransport::Le) { return; }
        if !s.le_reports.contains_key(&attr) { return; } // e.g. battery notifications
        let input = if s.boot {
            decode_boot_data(value, s.le_boot_kind == Some(1))
        } else {
            decode_report(&s.formats, value)
        };
        self.forward(device, &input);
        self.bus.publish(Event::HidReport { id: *device, input });
    }

    // ---- output (keyboard LEDs) ----

    /// Set the keyboard LED bitmask (numlock 0x01, caps 0x02, scroll 0x04).
    pub fn set_keyboard_leds(&self, device: &DeviceId, leds: u8) -> Result<()> {
        let s = self.st.lock().unwrap().get(device).cloned()
            .ok_or_else(|| Error::NotFound("hid session".into()))?;
        let HidTransport::Classic { control, .. } = s.transport else {
            // LE: write the (boot) output report characteristic — wired when gatt write API is used by GUI
            return Err(Error::NotSupported("LED control over GATT not wired yet".into()));
        };
        let mut pkt = vec![HIDP_SET_REPORT_OUT];
        if !s.boot {
            if let Some(id) = s.formats.iter().find(|f| f.kind == 1).and_then(|f| f.report_id) { pkt.push(id); }
        }
        pkt.push(leds);
        self.l2.send(control, &pkt)
    }

    // ---- forwarding to mitos-input ----

    fn forward(&self, device: &DeviceId, input: &HidInput) {
        let (kind, data): (&str, serde_json::Value) = match input {
            HidInput::Keyboard { modifiers, keys } => ("keyboard", json!({ "modifiers": modifiers, "keys": keys })),
            HidInput::Mouse { buttons, dx, dy, wheel } => ("mouse", json!({ "buttons": buttons, "dx": dx, "dy": dy, "wheel": wheel })),
            HidInput::Gamepad { buttons, axes } => ("gamepad", json!({ "buttons": buttons, "axes": axes })),
            HidInput::Raw(d) => ("raw", json!(crate::device::to_hex(d))),
        };
        let msg = json!({ "source": "bluetooth", "device": device.address.to_string(), "type": kind, "data": data });
        let line = serde_json::to_string(&msg).unwrap_or_default();
        let path = std::env::var("MITOS_INPUT_SOCK").unwrap_or_else(|_| "/tmp/mitos-input.sock".into());
        let mut guard = self.input_sock.lock().unwrap();
        if guard.is_none() {
            if let Ok(s) = UnixStream::connect(&path) { *guard = Some(s); }
        }
        if let Some(s) = guard.as_mut() {
            if writeln!(s, "{line}").and_then(|_| s.flush()).is_err() {
                *guard = None; // listener gone; retry next report
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KBD: &[u8] = &[
        0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x85, 0x01,
        0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02,
        0x95, 0x01, 0x75, 0x08, 0x81, 0x01,
        0x95, 0x06, 0x75, 0x08, 0x15, 0x00, 0x25, 0x65, 0x19, 0x00, 0x29, 0x65, 0x81, 0x00,
        0x05, 0x08, 0x19, 0x01, 0x29, 0x05, 0x15, 0x00, 0x25, 0x01, 0x95, 0x05, 0x75, 0x01, 0x91, 0x02,
        0x95, 0x01, 0x75, 0x03, 0x91, 0x01,
        0xC0,
    ];

    #[test]
    fn parse_and_decode_keyboard() {
        let formats = parse_descriptor(KBD);
        assert!(formats.iter().any(|f| f.kind == 0 && f.report_id == Some(1)));
        let data = [0x02, 0x00, 0x04, 0x05, 0x00, 0x00, 0x00, 0x00];
        let input = decode_report(&formats, &data);
        match input {
            HidInput::Keyboard { modifiers, keys } => {
                assert_eq!(modifiers, 0x02); // left shift
                assert_eq!(keys, vec![4, 5]); // 'a', 'b'
            }
            _ => panic!("expected keyboard"),
        }
    }

    const MOUSE: &[u8] = &[
        0x05, 0x01, 0x09, 0x02, 0xA1, 0x01, 0x85, 0x02,
        0x05, 0x09, 0x19, 0x01, 0x29, 0x03, 0x15, 0x00, 0x25, 0x01, 0x95, 0x03, 0x75, 0x01, 0x81, 0x02,
        0x95, 0x01, 0x75, 0x05, 0x81, 0x03,
        0x05, 0x01, 0x09, 0x30, 0x09, 0x31, 0x16, 0x01, 0x80, 0x26, 0xFF, 0x7F, 0x75, 0x08, 0x95, 0x02, 0x81, 0x06,
        0x09, 0x38, 0x15, 0x81, 0x25, 0x7F, 0x75, 0x08, 0x95, 0x01, 0x81, 0x06,
        0xC0,
    ];

    #[test]
    fn parse_and_decode_mouse() {
        let formats = parse_descriptor(MOUSE);
        let input = decode_report(&formats, &[0x02, 0x01, 0xFD, 0x05, 0x01]);
        match input {
            HidInput::Mouse { buttons, dx, dy, wheel } => {
                assert_eq!((buttons, dx, dy, wheel), (1, -3, 5, 1));
            }
            _ => panic!("expected mouse"),
        }
    }

    #[test]
    fn boot_decode() {
        match decode_boot_data(&[0x02, 0, 4, 0, 0, 0, 0, 0], false) {
            HidInput::Keyboard { modifiers, keys } => { assert_eq!(modifiers, 2); assert_eq!(keys, vec![4]); }
            _ => panic!(),
        }
        match decode_boot_data(&[0x01, 0xFE, 0x02], true) {
            HidInput::Mouse { buttons, dx, dy, wheel } => { assert_eq!((buttons, dx, dy, wheel), (1, -2, 2, 0)); }
            _ => panic!(),
        }
    }
}
