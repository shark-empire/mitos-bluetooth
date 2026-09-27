use crate::device::{DeviceId, DeviceTable};
use crate::error::{Error, Result};
use crate::events::{Event, EventBus};
use crate::l2cap::{L2cap, CID_ATT};
use serde::Serialize;
use std::collections::HashMap;
use std::fmt;
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::time::Duration;

mod att {
    pub const ERROR: u8 = 0x01;
    pub const MTU_REQ: u8 = 0x02;
    pub const FIND_INFO_REQ: u8 = 0x04;
    pub const READ_BY_TYPE_REQ: u8 = 0x08;
    pub const READ_REQ: u8 = 0x0a;
    pub const READ_BLOB_REQ: u8 = 0x0c;
    pub const READ_BY_GROUP_REQ: u8 = 0x10;
    pub const WRITE_REQ: u8 = 0x12;
    pub const WRITE_CMD: u8 = 0x52;
    pub const NOTIFY: u8 = 0x1b;
    pub const INDICATE: u8 = 0x1d;
    pub const CONFIRM: u8 = 0x1e;
    pub const ERR_ATTR_NOT_FOUND: u8 = 0x0a;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GattUuid(pub u128);

impl GattUuid {
    pub fn from_le16(b: &[u8]) -> Self { GattUuid(u16::from_le_bytes([b[0], b[1]]) as u128) }
    pub fn from_le128(b: &[u8]) -> Self { GattUuid(u128::from_le_bytes(b[..16].try_into().unwrap())) }
    pub fn as16(&self) -> Option<u16> { if self.0 <= 0xffff { Some(self.0 as u16) } else { None } }
}
impl fmt::Display for GattUuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as16() {
            Some(v) => write!(f, "0x{v:04x}"),
            None => {
                let h = format!("{:032x}", self.0);
                write!(f, "{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
            }
        }
    }
}
impl Serialize for GattUuid {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct GattService { pub start: u16, pub end: u16, pub uuid: GattUuid }

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GattCharacteristic {
    pub start_handle: u16,
    pub value_handle: u16,
    pub end_handle: u16,
    pub uuid: GattUuid,
    pub properties: u8,
    pub descriptors: Vec<GattDescriptor>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GattDescriptor { pub handle: u16, pub uuid: GattUuid }

struct GattConn {
    device: DeviceId,
    mtu: u16,
    pending: Option<(u8, std::sync::mpsc::Sender<Result<Vec<u8>>>)>,
    services: Option<Vec<GattService>>,
    chars: HashMap<u16, Vec<GattCharacteristic>>,
}

pub struct GattManager {
    pub l2: Arc<L2cap>,
    pub bus: Arc<EventBus>,
    pub devices: Arc<DeviceTable>,
    st: Mutex<HashMap<u16, GattConn>>,
}

impl GattManager {
    pub fn new(l2: Arc<L2cap>, bus: Arc<EventBus>, devices: Arc<DeviceTable>) -> Arc<Self> {
        Arc::new(GattManager { l2, bus, devices, st: Mutex::new(HashMap::new()) })
    }

    /// Attach the ATT bearer to an LE connection (called when the link comes up).
    pub fn attach(self: &Arc<Self>, handle: u16, device: DeviceId) -> Result<()> {
        let (tx, rx) = channel();
        {
            let mut st = self.st.lock().unwrap();
            if st.contains_key(&handle) { return Ok(()); }
            self.l2.register_fixed(handle, CID_ATT, tx);
            st.insert(handle, GattConn { device, mtu: 23, pending: None, services: None, chars: HashMap::new() });
        }
        let mgr = self.clone();
        std::thread::Builder::new().name("att".into()).spawn(move || {
            while let Ok(p) = rx.recv() {
                if p.closed { mgr.st.lock().unwrap().remove(&p.handle); break; }
                mgr.on_att(p.handle, &p.data);
            }
        }).ok();
        // negotiate a larger MTU (best-effort; default stays 23 if it fails)
        if let Ok(d) = self.request(handle, att::MTU_REQ, &247u16.to_le_bytes()) {
            if let Some(m) = d.first().and_then(|_| d.get(1)) {
                let server = u16::from_le_bytes([d[0], d[1]]);
                let mut st = self.st.lock().unwrap();
                if let Some(c) = st.get_mut(&handle) { c.mtu = 247u16.min(server).max(23); }
                let _ = m;
            }
        }
        Ok(())
    }

    pub fn detach(&self, handle: u16) {
        self.l2.unregister_fixed(handle, CID_ATT);
        if let Some(c) = self.st.lock().unwrap().remove(&handle) {
            if let Some((_, tx)) = c.pending { let _ = tx.send(Err(Error::InvalidState("gatt detached".into()))); }
        }
    }

    /// Sequential ATT request/response exchange.
    fn request(&self, conn: u16, opcode: u8, params: &[u8]) -> Result<Vec<u8>> {
        let (tx, rx) = channel();
        {
            let mut st = self.st.lock().unwrap();
            let c = st.get_mut(&conn).ok_or_else(|| Error::InvalidState("gatt not attached".into()))?;
            if c.pending.is_some() { return Err(Error::InvalidState("gatt request already in flight".into())); }
            c.pending = Some((opcode, tx));
        }
        let mut pkt = vec![opcode];
        pkt.extend_from_slice(params);
        if let Err(e) = self.l2.send_fixed(conn, CID_ATT, &pkt) {
            if let Some(c) = self.st.lock().unwrap().get_mut(&conn) { c.pending = None; }
            return Err(e);
        }
        match rx.recv_timeout(Duration::from_secs(10)) {
            Ok(r) => r,
            Err(_) => {
                if let Some(c) = self.st.lock().unwrap().get_mut(&conn) { c.pending = None; }
                Err(Error::Timeout("att response"))
            }
        }
    }

    fn on_att(&self, conn: u16, data: &[u8]) {
        let Some(&op) = data.first() else { return };
        let mut notify: Option<(DeviceId, u16, Vec<u8>)> = None;
        let mut confirm = false;
        {
            let mut st = self.st.lock().unwrap();
            let Some(c) = st.get_mut(&conn) else { return };
            let pending = c.pending.take();
            if let Some((req, tx)) = pending {
                if op == att::ERROR && data.len() >= 4 {
                    let _ = tx.send(Err(Error::Att { code: data[1], handle: u16::from_le_bytes([data[2], data[3]]) }));
                } else if op == req + 1 {
                    if op == att::MTU_REQ + 1 && data.len() >= 3 {
                        let server = u16::from_le_bytes([data[1], data[2]]);
                        c.mtu = 247u16.min(server).max(23);
                    }
                    let _ = tx.send(Ok(data[1..].to_vec()));
                } else {
                    // a notification/indication can interleave with a pending request
                    c.pending = Some((req, tx));
                    if (op == att::NOTIFY || op == att::INDICATE) && data.len() >= 3 {
                        notify = Some((c.device, u16::from_le_bytes([data[1], data[2]]), data[3..].to_vec()));
                        confirm = op == att::INDICATE;
                    }
                }
            } else if (op == att::NOTIFY || op == att::INDICATE) && data.len() >= 3 {
                notify = Some((c.device, u16::from_le_bytes([data[1], data[2]]), data[3..].to_vec()));
                confirm = op == att::INDICATE;
            }
        }
        if confirm { let _ = self.l2.send_fixed(conn, CID_ATT, &[att::CONFIRM]); }
        if let Some((device, attribute, value)) = notify {
            self.bus.publish(Event::GattNotification { id: device, attribute, value });
        }
    }

    // ---- discovery ----

    pub fn discover_services(&self, conn: u16) -> Result<Vec<GattService>> {
        {
            let st = self.st.lock().unwrap();
            if let Some(c) = st.get(&conn) { if let Some(s) = &c.services { return Ok(s.clone()); } }
        }
        let mut services = Vec::new();
        let mut start: u16 = 0x0001;
        loop {
            let params = [start.to_le_bytes(), 0xFFFFu16.to_le_bytes(), 0x00, 0x28].concat();
            match self.request(conn, att::READ_BY_GROUP_REQ, &params) {
                Ok(data) => {
                    let item_len = *data.first().unwrap_or(&0) as usize;
                    let before = services.len();
                    let mut off = 1;
                    while item_len >= 6 && off + item_len <= data.len() {
                        let sh = u16::from_le_bytes([data[off], data[off + 1]]);
                        let eh = u16::from_le_bytes([data[off + 2], data[off + 3]]);
                        let uuid = if item_len == 6 { GattUuid::from_le16(&data[off + 4..]) }
                                   else { GattUuid::from_le128(&data[off + 4..]) };
                        services.push(GattService { start: sh, end: eh, uuid });
                        off += item_len;
                    }
                    if services.len() == before { break; }
                    start = services.last().unwrap().end.wrapping_add(1);
                    if start == 0 || start > 0xFFFF { break; }
                }
                Err(Error::Att { code: att::ERR_ATTR_NOT_FOUND, .. }) => break, // normal terminator
                Err(e) => return Err(e),
            }
        }
        let mut st = self.st.lock().unwrap();
        if let Some(c) = st.get_mut(&conn) { c.services = Some(services.clone()); }
        Ok(services)
    }

    pub fn discover_characteristics(&self, conn: u16, service: &GattService) -> Result<Vec<GattCharacteristic>> {
        {
            let st = self.st.lock().unwrap();
            if let Some(c) = st.get(&conn) {
                if let Some(v) = c.chars.get(&service.start) { return Ok(v.clone()); }
            }
        }
        let mut chars: Vec<GattCharacteristic> = Vec::new();
        let mut start = service.start.max(1);
        loop {
            let params = [start.to_le_bytes(), service.end.to_le_bytes(), 0x03, 0x28].concat();
            match self.request(conn, att::READ_BY_TYPE_REQ, &params) {
                Ok(data) => {
                    let item_len = *data.first().unwrap_or(&0) as usize;
                    let before = chars.len();
                    let mut off = 1;
                    while item_len >= 6 && off + item_len <= data.len() {
                        let decl = u16::from_le_bytes([data[off], data[off + 1]]);
                        let props = data[off + 2];
                        let vh = u16::from_le_bytes([data[off + 3], data[off + 4]]);
                        let uuid = if item_len == 7 { GattUuid::from_le16(&data[off + 5..]) }
                                   else { GattUuid::from_le128(&data[off + 5..]) };
                        chars.push(GattCharacteristic { start_handle: decl, value_handle: vh, end_handle: 0, uuid, props, descriptors: Vec::new() });
                        off += item_len;
                    }
                    if chars.len() == before { break; }
                    start = chars.last().unwrap().start_handle.wrapping_add(1);
                    if start == 0 || start > service.end { break; }
                }
                Err(Error::Att { code: att::ERR_ATTR_NOT_FOUND, .. }) => break,
                Err(e) => return Err(e),
            }
        }
        for i in 0..chars.len() {
            chars[i].end_handle = if i + 1 < chars.len() { chars[i + 1].start_handle - 1 } else { service.end };
        }
        for ch in chars.iter_mut() {
            if ch.end_handle > ch.value_handle {
                ch.descriptors = self.find_descriptors(conn, ch.value_handle + 1, ch.end_handle).unwrap_or_default();
            }
        }
        let mut st = self.st.lock().unwrap();
        if let Some(c) = st.get_mut(&conn) { c.chars.insert(service.start, chars.clone()); }
        Ok(chars)
    }

    fn find_descriptors(&self, conn: u16, mut start: u16, end: u16) -> Result<Vec<GattDescriptor>> {
        let mut out = Vec::new();
        if start > end { return Ok(out); }
        loop {
            let params = [start.to_le_bytes(), end.to_le_bytes()].concat();
            match self.request(conn, att::FIND_INFO_REQ, &params) {
                Ok(data) => {
                    if data.len() < 3 { break; }
                    let fmt = data[0];
                    let pair = if fmt == 1 { 4usize } else if fmt == 2 { 18 } else { break };
                    let mut off = 1;
                    let mut added = 0;
                    while off + pair <= data.len() {
                        let h = u16::from_le_bytes([data[off], data[off + 1]]);
                        let uuid = if fmt == 1 { GattUuid::from_le16(&data[off + 2..]) }
                                   else { GattUuid::from_le128(&data[off + 2..]) };
                        out.push(GattDescriptor { handle: h, uuid });
                        start = h.wrapping_add(1);
                        added += 1;
                        off += pair;
                    }
                    if added == 0 || start == 0 || start > end { break; }
                }
                Err(_) => break,
            }
        }
        Ok(out)
    }

    // ---- read / write / subscribe ----

    pub fn read(&self, conn: u16, attr: u16) -> Result<Vec<u8>> {
        let mtu = self.st.lock().unwrap().get(&conn).map(|c| c.mtu).unwrap_or(23) as usize;
        let mut out = self.request(conn, att::READ_REQ, &attr.to_le_bytes())?;
        while out.len() >= mtu.saturating_sub(1) && out.len() < 512 {
            let params = [&attr.to_le_bytes(), &(out.len() as u16).to_le_bytes()].concat();
            match self.request(conn, att::READ_BLOB_REQ, &params) {
                Ok(d) if !d.is_empty() => {
                    let n = d.len();
                    out.extend_from_slice(&d);
                    if n < mtu.saturating_sub(1) { break; }
                }
                _ => break,
            }
        }
        Ok(out)
    }

    pub fn write(&self, conn: u16, attr: u16, data: &[u8], response: bool) -> Result<()> {
        if response {
            let params = [&attr.to_le_bytes(), data].concat();
            self.request(conn, att::WRITE_REQ, &params)?;
            Ok(())
        } else {
            let mut pkt = vec![att::WRITE_CMD];
            pkt.extend_from_slice(&attr.to_le_bytes());
            pkt.extend_from_slice(data);
            self.l2.send_fixed(conn, CID_ATT, &pkt)
        }
    }

    /// Enable notifications (1) or indications (2) on a characteristic (writes its CCC).
    pub fn subscribe(&self, conn: u16, value_handle: u16, cccd_value: u16) -> Result<()> {
        let cccd = {
            let st = self.st.lock().unwrap();
            let mut found = None;
            if let Some(c) = st.get(&conn) {
                'outer: for list in c.chars.values() {
                    for ch in list {
                        if (ch.start_handle..=ch.end_handle).contains(&value_handle) {
                            for d in &ch.descriptors {
                                if d.uuid.as16() == Some(0x2902) { found = Some(d.handle); break 'outer; }
                            }
                        }
                    }
                }
            }
            found.unwrap_or(value_handle + 1)
        };
        self.write(conn, cccd, &cccd_value.to_le_bytes(), true)
    }
}