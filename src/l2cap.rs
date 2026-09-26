use crate::device::DeviceId;
use crate::error::{Error, Result};
use crate::hci::{AclSdu, HciClient};
use std::collections::HashMap;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const PSM_SDP: u16 = 0x0001;
pub const PSM_RFCOMM: u16 = 0x0003;
pub const PSM_HID_CONTROL: u16 = 0x0011;
pub const PSM_HID_INTERRUPT: u16 = 0x0013;
pub const PSM_AVCTP: u16 = 0x0017;
pub const PSM_AVDTP: u16 = 0x0019;
pub const CID_SIGNALING: u16 = 0x0001;
pub const CID_ATT: u16 = 0x0004;
pub const CID_LE_SIGNALING: u16 = 0x0005;
pub const CID_SMP: u16 = 0x0006;

pub struct L2Packet { pub handle: u16, pub cid: u16, pub psm: u16, pub data: Vec<u8>, pub closed: bool }

struct Channel { handle: u16, remote_cid: u16, psm: u16 }
struct L2State {
    next_cid: u16,
    next_ident: u8,
    channels: HashMap<u16, Channel>,
    waiters: HashMap<u8, Sender<(u8, Vec<u8>)>>,
    handlers: HashMap<u16, Sender<L2Packet>>,
    fixed: HashMap<(u16, u16), Sender<L2Packet>>,
    listeners: HashMap<u16, Sender<L2Packet>>,
    devices: HashMap<u16, DeviceId>,
}

pub struct L2cap { hci: Arc<HciClient>, st: Mutex<L2State> }

fn le16(b: &[u8], o: usize) -> u16 { u16::from_le_bytes([b[o], b[o + 1]]) }

impl L2cap {
    pub fn new(hci: Arc<HciClient>) -> Arc<Self> {
        let (tx, rx): (Sender<AclSdu>, Receiver<AclSdu>) = channel();
        hci.set_acl_handler(tx);
        let l2 = Arc::new(L2cap {
            hci,
            st: Mutex::new(L2State { next_cid: 0x40, next_ident: 1, channels: HashMap::new(), waiters: HashMap::new(), handlers: HashMap::new(), fixed: HashMap::new(), listeners: HashMap::new(), devices: HashMap::new() }),
        });
        let l = l2.clone();
        std::thread::Builder::new().name("l2cap".into()).spawn(move || {
            while let Ok(sdu) = rx.recv() { l.on_sdu(sdu); }
        }).ok();
        l2
    }

    pub fn set_device(&self, handle: u16, id: DeviceId) { self.st.lock().unwrap().devices.insert(handle, id); }
    pub fn device(&self, handle: u16) -> Option<DeviceId> { self.st.lock().unwrap().devices.get(&handle).copied() }

    pub fn register_handler(&self, cid: u16, tx: Sender<L2Packet>) { self.st.lock().unwrap().handlers.insert(cid, tx); }
    pub fn register_fixed(&self, handle: u16, cid: u16, tx: Sender<L2Packet>) { self.st.lock().unwrap().fixed.insert((handle, cid), tx); }
    pub fn unregister_fixed(&self, handle: u16, cid: u16) { self.st.lock().unwrap().fixed.remove(&(handle, cid)); }
    pub fn register_listener(&self, psm: u16, tx: Sender<L2Packet>) { self.st.lock().unwrap().listeners.insert(psm, tx); }

    pub fn cleanup_handle(&self, handle: u16) {
        let mut st = self.st.lock().unwrap();
        let dead: Vec<u16> = st.channels.iter().filter(|(_, c)| c.handle == handle).map(|(k, _)| *k).collect();
        for cid in &dead {
            if let Some(tx) = st.handlers.get(cid) { let _ = tx.send(L2Packet { handle, cid: *cid, psm: 0, data: Vec::new(), closed: true }); }
            st.channels.remove(cid);
            st.handlers.remove(cid);
        }
        st.fixed.retain(|(h, _), _| *h != handle);
        st.devices.remove(&handle);
    }

    pub fn connect(&self, handle: u16, psm: u16) -> Result<u16> {
        let (scid, ident, rx) = {
            let mut st = self.st.lock().unwrap();
            let scid = st.next_cid;
            st.next_cid += 1;
            if st.next_cid > 0x7fff { st.next_cid = 0x40; }
            let ident = st.next_ident;
            st.next_ident = st.next_ident.wrapping_add(1);
            if st.next_ident == 0 { st.next_ident = 1; }
            let (tx, rx) = channel();
            st.waiters.insert(ident, tx);
            st.channels.insert(scid, Channel { handle, remote_cid: 0, psm });
            (scid, ident, rx)
        };
        // Connection Request: [psm][scid]
        let resp = match self.sig_request(handle, 0x02, ident, &psm.to_le_bytes(), &scid.to_le_bytes()) ...and_then(|_| rx_recv(rx, ident, self, 10))?; {
            Ok(v) => v,
            Err(e) => { let mut st = self.st.lock().unwrap(); st.channels.remove(&scid); st.waiters.remove(&ident); return Err(e); }
        };
        if resp.0 != 0x03 { return Err(Error::L2cap(format!("unexpected response 0x{:02x}", resp.0))); }
        let dcid = le16(&resp.1, 0);
        let result = le16(&resp.1, 4);
        if result != 0 { let mut st = self.st.lock().unwrap(); st.channels.remove(&scid); return Err(Error::L2cap(format!("connection refused on psm 0x{psm:04x}: result {result}"))); }
        { let mut st = self.st.lock().unwrap(); st.channels.get_mut(&scid).unwrap().remote_cid = dcid; }

        // Configure: advertise our MTU. Remote config request is auto-answered in on_signaling.
        let (ident2, rx2) = { let mut st = self.st.lock().unwrap(); let i = st.next_ident; st.next_ident = if st.next_ident == 255 { 1 } else { st.next_ident + 1 }; let (tx, rx) = channel(); st.waiters.insert(i, tx); (i, rx) };
        let mut payload = dcid.to_le_bytes().to_vec();
        payload.extend_from_slice(&0u16.to_le_bytes());
        payload.extend_from_slice(&[0x01, 0x02]); // MTU option
        payload.extend_from_slice(&672u16.to_le_bytes());
        let r2 = self.sig_request(handle, 0x04, ident2, &payload)...and_then(|_| rx_recv(rx, ident, self, 10))?;
        match r2 {
            Ok((0x05, data)) if data.len() >= 4 => {
                let mut i = 4;
                let mut result = 0u16;
                while i + 2 <= data.len() {
                    let t = data[i]; let l = data[i + 1] as usize;
                    if t == 0x04 && i + 2 + 2 <= data.len() { result = le16(&data, i + 2); }
                    i += 2 + l;
                }
                if result != 0 && result != 0x0002 { return Err(Error::L2cap(format!("configure failed: {result}"))); }
            }
            Ok((c, _)) => return Err(Error::L2cap(format!("unexpected configure response 0x{c:02x}"))),
            Err(e) => return Err(e),
        }
        Ok(scid)
    }

    pub fn send(&self, cid: u16, data: &[u8]) -> Result<()> {
        let (handle, rcid) = {
            let st = self.st.lock().unwrap();
            let c = st.channels.get(&cid).ok_or_else(|| Error::L2cap(format!("unknown cid 0x{cid:04x}")))?;
            (c.handle, c.remote_cid)
        };
        self.send_fixed(handle, rcid, data)
    }

    pub fn send_fixed(&self, handle: u16, cid: u16, data: &[u8]) -> Result<()> {
        let mut pdu = Vec::with_capacity(4 + data.len());
        pdu.extend_from_slice(&(data.len() as u16).to_le_bytes());
        pdu.extend_from_slice(&cid.to_le_bytes());
        pdu.extend_from_slice(data);
        self.hci.send_acl(handle, &pdu)
    }

    pub fn disconnect(&self, cid: u16) -> Result<()> {
        let (handle, rcid, psm) = {
            let st = self.st.lock().unwrap();
            match st.channels.get(&cid) { Some(c) => (c.handle, c.remote_cid, c.psm), None => return Ok(()) }
        };
        let (ident, rx) = { let mut st = self.st.lock().unwrap(); let i = st.next_ident; st.next_ident = if st.next_ident == 255 { 1 } else { st.next_ident + 1 }; let (tx, rx) = channel(); st.waiters.insert(i, tx); (i, rx) };
        let mut payload = rcid.to_le_bytes().to_vec();
        payload.extend_from_slice(&cid.to_le_bytes());
        let _ = self.sig_request(handle, 0x06, ident, &payload)...and_then(|_| rx_recv(rx, ident, self, 10))?;
        let mut st = self.st.lock().unwrap();
        st.channels.remove(&cid);
        if let Some(tx) = st.handlers.remove(&cid) { let _ = tx.send(L2Packet { handle, cid, psm, data: Vec::new(), closed: true }); }
        Ok(())
    }

    fn sig_request(&self, handle: u16, code: u8, ident: u8, payload: &[u8]) -> Result<()> {
        let mut p = Vec::with_capacity(4 + payload.len());
        p.push(code); p.push(ident);
        p.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        p.extend_from_slice(payload);
        self.send_fixed(handle, CID_SIGNALING, &p)
    }

    fn on_sdu(&self, sdu: AclSdu) {
        if sdu.cid == CID_SIGNALING { self.on_signaling(sdu.handle, &sdu.data); }
        else if sdu.cid == CID_LE_SIGNALING { self.on_le_signaling(sdu.handle, &sdu.data); }
        else {
            let st = self.st.lock().unwrap();
            if let Some(tx) = st.fixed.get(&(sdu.handle, sdu.cid)) {
                let _ = tx.send(L2Packet { handle: sdu.handle, cid: sdu.cid, psm: 0, data: sdu.data, closed: false });
                return;
            }
            if let Some(ch) = st.channels.get(&sdu.cid) {
                if ch.handle == sdu.handle {
                    if let Some(tx) = st.handlers.get(&sdu.cid) {
                        let _ = tx.send(L2Packet { handle: sdu.handle, cid: sdu.cid, psm: ch.psm, data: sdu.data, closed: false });
                    }
                }
            }
        }
    }

    fn on_le_signaling(&self, handle: u16, data: &[u8]) {
        let mut i = 0;
        while i + 4 <= data.len() {
            let code = data[i]; let ident = data[i + 1]; let len = le16(data, i + 2) as usize;
            let payload = data.get(i + 4..i + 4 + len).unwrap_or(&[]);
            if code == 0x12 { // Connection Parameter Update Request -> accept
                let mut p = vec![0x01, ident, 0x02, 0x00, 0x00, 0x00];
                p.extend_from_slice(&0u16.to_le_bytes());
                let _ = self.send_fixed(handle, CID_LE_SIGNALING, &p);
            }
            i += 4 + len;
        }
    }

    fn on_signaling(&self, handle: u16, data: &[u8]) {
        let mut i = 0;
        while i + 4 <= data.len() {
            let code = data[i]; let ident = data[i + 1]; let len = le16(data, i + 2) as usize;
            let payload = data.get(i + 4..i + 4 + len).unwrap_or(&[]).to_vec();
            let is_response = matches!(code, 0x01 | 0x03 | 0x05 | 0x07 | 0x09 | 0x0b | 0x0d | 0x0f | 0x11 | 0x13);
            if is_response {
                let waiter = self.st.lock().unwrap().waiters.remove(&ident);
                if let Some(tx) = waiter { let _ = tx.send((code, payload)); }
                i += 4 + len;
                continue;
            }
            match code {
                0x02 => { // inbound Connection Request: [psm][scid]
                    if payload.len() >= 4 {
                        let psm = le16(&payload, 0); let their = le16(&payload, 2);
                        let listener = self.st.lock().unwrap().listeners.get(&psm).cloned();
                        if let Some(tx) = listener {
                            let mut st = self.st.lock().unwrap();
                            let dcid = st.next_cid; st.next_cid += 1;
                            st.channels.insert(dcid, Channel { handle, remote_cid: their, psm });
                            drop(st);
                            let mut resp = vec![dcid as u8, (dcid >> 8) as u8];
                            resp.extend_from_slice(&their.to_le_bytes());
                            resp.extend_from_slice(&0u16.to_le_bytes()); // result: success
                            resp.extend_from_slice(&0u16.to_le_bytes()); // status
                            let _ = self.sig_request(handle, 0x03, ident, &resp);
                            let _ = tx.send(L2Packet { handle, cid: dcid, psm, data: Vec::new(), closed: false });
                        } else {
                            // reject: connection refused
                            let mut resp = le16(&payload, 2).to_le_bytes().to_vec();
                            resp.extend_from_slice(&[0, 0]);
                            resp.extend_from_slice(&0x0002u16.to_le_bytes());
                            resp.extend_from_slice(&[0, 0]);
                            let _ = self.sig_request(handle, 0x03, ident, &resp);
                        }
                    }
                }
                0x04 => { // inbound Configure Request: [dcid(ours)][flags][opts] -> answer OK
                    if payload.len() >= 4 {
                        let mut resp = payload[..2].to_vec();
                        resp.extend_from_slice(&0u16.to_le_bytes());
                        resp.extend_from_slice(&[0x04, 0x02, 0x00, 0x00]); // result option: success
                        let _ = self.sig_request(handle, 0x05, ident, &resp);
                    }
                }
                0x06 => { // inbound Disconnect Request: [dcid(ours)][scid(theirs)]
                    if payload.len() >= 4 {
                        let ours = le16(&payload, 0); let theirs = le16(&payload, 2);
                        let mut resp = theirs.to_le_bytes().to_vec();
                        resp.extend_from_slice(&ours.to_le_bytes());
                        let _ = self.sig_request(handle, 0x07, ident, &resp);
                        let mut st = self.st.lock().unwrap();
                        st.channels.remove(&ours);
                        if let Some(tx) = st.handlers.remove(&ours) { let _ = tx.send(L2Packet { handle, cid: ours, psm: 0, data: Vec::new(), closed: true }); }
                    }
                }
                _ => {
                    // command reject for anything we don't handle
                    let mut resp = vec![ident, 0x01, 0x02, 0x00];
                    resp.extend_from_slice(&0u16.to_le_bytes());
                    let p = vec![0x01, ident, 0x02, 0x00, 0x00, 0x00];
                    p.extend_from_slice(&resp);
                    let _ = self.send_fixed(handle, CID_SIGNALING, &p);
                }
            }
            i += 4 + len;
        }
    }
}

// small helper so we can clean waiters on failure paths
impl L2cap {
    fn drop_waiter(&self, ident: u8) { self.st.lock().unwrap().waiters.remove(&ident); }
}

fn rx_recv(rx: Receiver<(u8, Vec<u8>)>, ident: u8, l2: &L2cap, secs: u64) -> Result<(u8, Vec<u8>)> {
    match rx.recv_timeout(Duration::from_secs(secs)) {
        Ok((code, data)) => {
            if code == 0x01 { l2.drop_waiter(ident); Err(Error::L2cap("signaling command rejected".into())) }
            else { Ok((code, data)) }
        }
        Err(_) => { l2.drop_waiter(ident); Err(Error::Timeout("l2cap signaling")) }
    }
}