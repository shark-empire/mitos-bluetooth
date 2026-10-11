use crate::device::{AddressType, DeviceId};
use crate::error::{Error, Result};
use crate::hci::{AclSdu, HciClient};
use std::collections::HashMap;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

/// Spec default L2CAP MTU (in force until the peer's configure request says otherwise) and the spec minimum.
pub const DEFAULT_MTU: u16 = 672;
pub const MIN_MTU: u16 = 48;

pub struct L2Packet {
    pub handle: u16,
    pub cid: u16,
    pub psm: u16,
    pub data: Vec<u8>,
    pub closed: bool,
}

struct Channel {
    handle: u16,
    remote_cid: u16,
    psm: u16,
    mtu: u16,
}

type Reply = (u8, Vec<u8>);

struct L2State {
    next_cid: u16,
    next_ident: u8,
    channels: HashMap<u16, Channel>,
    waiters: HashMap<u8, Sender<Reply>>,
    handlers: HashMap<u16, Sender<L2Packet>>,
    fixed: HashMap<(u16, u16), Sender<L2Packet>>,
    listeners: HashMap<u16, Sender<L2Packet>>,
    devices: HashMap<u16, DeviceId>,
}

pub struct L2cap {
    hci: Arc<HciClient>,
    st: Mutex<L2State>,
}

/// Little-endian u16 at `o`; bytes past the end read as zero so short PDUs can never panic.
fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b.get(o).copied().unwrap_or(0), b.get(o + 1).copied().unwrap_or(0)])
}

fn alloc_cid(st: &mut L2State) -> u16 {
    loop {
        let c = st.next_cid;
        st.next_cid = if c >= 0x7fff { 0x40 } else { c + 1 };
        if !st.channels.contains_key(&c) {
            return c;
        }
    }
}

/// Signaling identifiers are 1..=255; 0 is invalid and ones with a caller waiting are skipped.
fn alloc_ident(st: &mut L2State) -> u8 {
    loop {
        let i = st.next_ident;
        st.next_ident = if i == 255 { 1 } else { i + 1 };
        if i != 0 && !st.waiters.contains_key(&i) {
            return i;
        }
    }
}

fn is_response(code: u8) -> bool {
    matches!(code, 0x01 | 0x03 | 0x05 | 0x07 | 0x09 | 0x0b | 0x0d | 0x0f | 0x11 | 0x13)
}

fn rx_recv(rx: &Receiver<Reply>, timeout: Duration) -> Result<Reply> {
    rx.recv_timeout(timeout).map_err(|_| Error::Timeout("l2cap signaling"))
}

impl L2cap {
    pub fn new(hci: Arc<HciClient>) -> Arc<Self> {
        let (tx, rx): (Sender<AclSdu>, Receiver<AclSdu>) = channel();
        hci.set_acl_handler(tx);
        let l2 = Arc::new(L2cap {
            hci,
            st: Mutex::new(L2State {
                next_cid: 0x40,
                next_ident: 1,
                channels: HashMap::new(),
                waiters: HashMap::new(),
                handlers: HashMap::new(),
                fixed: HashMap::new(),
                listeners: HashMap::new(),
                devices: HashMap::new(),
            }),
        });
        // The worker only holds a Weak reference: when the last owner lets go of the L2CAP layer it unwinds.
        let weak = Arc::downgrade(&l2);
        std::thread::Builder::new()
            .name("l2cap".into())
            .spawn(move || {
                while let Ok(sdu) = rx.recv() {
                    match weak.upgrade() {
                        Some(l) => l.on_sdu(sdu),
                        None => break,
                    }
                }
            })
            .ok();
        l2
    }

    /// Drop every channel, handler and listener so the threads waiting on them can finish.
    pub fn shutdown(&self) {
        let mut st = self.st.lock().unwrap();
        st.channels.clear();
        st.waiters.clear();
        st.handlers.clear();
        st.fixed.clear();
        st.listeners.clear();
        st.devices.clear();
    }

    pub fn set_device(&self, handle: u16, id: DeviceId) {
        self.st.lock().unwrap().devices.insert(handle, id);
    }

    pub fn device(&self, handle: u16) -> Option<DeviceId> {
        self.st.lock().unwrap().devices.get(&handle).copied()
    }

    pub fn register_handler(&self, cid: u16, tx: Sender<L2Packet>) {
        self.st.lock().unwrap().handlers.insert(cid, tx);
    }

    pub fn register_fixed(&self, handle: u16, cid: u16, tx: Sender<L2Packet>) {
        self.st.lock().unwrap().fixed.insert((handle, cid), tx);
    }

    pub fn unregister_fixed(&self, handle: u16, cid: u16) {
        self.st.lock().unwrap().fixed.remove(&(handle, cid));
    }

    pub fn register_listener(&self, psm: u16, tx: Sender<L2Packet>) {
        self.st.lock().unwrap().listeners.insert(psm, tx);
    }

    pub fn cleanup_handle(&self, handle: u16) {
        let mut st = self.st.lock().unwrap();
        let dead: Vec<u16> = st.channels.iter().filter(|(_, c)| c.handle == handle).map(|(k, _)| *k).collect();
        for cid in &dead {
            if let Some(tx) = st.handlers.get(cid) {
                let _ = tx.send(L2Packet { handle, cid: *cid, psm: 0, data: Vec::new(), closed: true });
            }
            st.channels.remove(cid);
            st.handlers.remove(cid);
        }
        st.fixed.retain(|(h, _), _| *h != handle);
        st.devices.remove(&handle);
    }

    /// Open a connection-oriented channel to `psm` and configure both directions.
    pub fn connect(&self, handle: u16, psm: u16) -> Result<u16> {
        let (scid, ident, rx) = {
            let mut st = self.st.lock().unwrap();
            let scid = alloc_cid(&mut st);
            let ident = alloc_ident(&mut st);
            let (tx, rx) = channel();
            st.waiters.insert(ident, tx);
            st.channels.insert(scid, Channel { handle, remote_cid: 0, psm, mtu: DEFAULT_MTU });
            (scid, ident, rx)
        };
        let abort = |e: Error| -> Error {
            let mut st = self.st.lock().unwrap();
            st.channels.remove(&scid);
            st.waiters.remove(&ident);
            e
        };
        let mut req = psm.to_le_bytes().to_vec();
        req.extend_from_slice(&scid.to_le_bytes());
        if let Err(e) = self.sig_request(handle, 0x02, ident, &req) {
            return Err(abort(e));
        }
        // The peer may answer "pending" (result 1) while it authenticates the link or asks its user:
        // keep waiting on the same identifier until the final answer arrives.
        let deadline = Instant::now() + Duration::from_secs(30);
        let dcid = loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let (code, data) = match rx_recv(&rx, left) {
                Ok(r) => r,
                Err(e) => return Err(abort(e)),
            };
            if code == 0x01 {
                return Err(abort(Error::L2cap("signaling command rejected".into())));
            }
            if code != 0x03 || data.len() < 8 {
                return Err(abort(Error::L2cap("malformed connection response".into())));
            }
            match le16(&data, 4) {
                0 => break le16(&data, 0),
                1 => continue,
                r => return Err(abort(Error::L2cap(format!("connection refused on psm 0x{psm:04x} (result {r})")))),
            }
        };
        if let Some(c) = self.st.lock().unwrap().channels.get_mut(&scid) {
            c.remote_cid = dcid;
        }

        // our Configure Request: advertise our receive MTU
        let (cfg_ident, cfg_rx) = {
            let mut st = self.st.lock().unwrap();
            let i = alloc_ident(&mut st);
            let (tx, rx) = channel();
            st.waiters.insert(i, tx);
            (i, rx)
        };
        let mut cfg = dcid.to_le_bytes().to_vec();
        cfg.extend_from_slice(&0u16.to_le_bytes()); // flags
        cfg.extend_from_slice(&[0x01, 0x02]); // MTU option
        cfg.extend_from_slice(&DEFAULT_MTU.to_le_bytes());
        if let Err(e) = self.sig_request(handle, 0x04, cfg_ident, &cfg) {
            self.drop_waiter(cfg_ident);
            return Err(abort(e));
        }
        match rx_recv(&cfg_rx, Duration::from_secs(10)) {
            Ok((0x05, data)) if data.len() >= 6 && le16(&data, 4) == 0 => Ok(scid),
            Ok((0x05, data)) => {
                let result = le16(&data, 4);
                Err(abort(Error::L2cap(format!("configuration refused (result {result})"))))
            }
            Ok(_) => Err(abort(Error::L2cap("configuration rejected".into()))),
            Err(e) => {
                self.drop_waiter(cfg_ident);
                Err(abort(e))
            }
        }
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
        let le = self
            .st
            .lock()
            .unwrap()
            .devices
            .get(&handle)
            .is_some_and(|d| d.address_type != AddressType::Bredr);
        let mut pdu = Vec::with_capacity(4 + data.len());
        pdu.extend_from_slice(&(data.len() as u16).to_le_bytes());
        pdu.extend_from_slice(&cid.to_le_bytes());
        pdu.extend_from_slice(data);
        self.hci.send_acl(handle, le, &pdu)
    }

    pub fn disconnect(&self, cid: u16) -> Result<()> {
        let (handle, rcid, psm) = {
            let st = self.st.lock().unwrap();
            match st.channels.get(&cid) {
                Some(c) => (c.handle, c.remote_cid, c.psm),
                None => return Ok(()),
            }
        };
        let (ident, rx) = {
            let mut st = self.st.lock().unwrap();
            let i = alloc_ident(&mut st);
            let (tx, rx) = channel();
            st.waiters.insert(i, tx);
            (i, rx)
        };
        let mut payload = rcid.to_le_bytes().to_vec();
        payload.extend_from_slice(&cid.to_le_bytes());
        if self.sig_request(handle, 0x06, ident, &payload).is_ok() {
            let _ = rx_recv(&rx, Duration::from_secs(3));
        }
        self.drop_waiter(ident);
        let mut st = self.st.lock().unwrap();
        st.channels.remove(&cid);
        if let Some(tx) = st.handlers.remove(&cid) {
            let _ = tx.send(L2Packet { handle, cid, psm, data: Vec::new(), closed: true });
        }
        Ok(())
    }

    fn sig_request(&self, handle: u16, code: u8, ident: u8, payload: &[u8]) -> Result<()> {
        let mut p = Vec::with_capacity(4 + payload.len());
        p.push(code);
        p.push(ident);
        p.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        p.extend_from_slice(payload);
        self.send_fixed(handle, CID_SIGNALING, &p)
    }

    fn drop_waiter(&self, ident: u8) {
        self.st.lock().unwrap().waiters.remove(&ident);
    }

    /// Peer's receive MTU for a channel (the max SDU we may send it).
    pub fn remote_mtu(&self, cid: u16) -> u16 {
        self.st.lock().unwrap().channels.get(&cid).map_or(MIN_MTU, |c| c.mtu)
    }

    fn on_sdu(&self, sdu: AclSdu) {
        if sdu.cid == CID_SIGNALING {
            self.on_signaling(sdu.handle, &sdu.data);
        } else if sdu.cid == CID_LE_SIGNALING {
            self.on_le_signaling(sdu.handle, &sdu.data);
        } else {
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
            let code = data[i];
            let ident = data[i + 1];
            let len = usize::from(le16(data, i + 2));
            let payload = data.get(i + 4..i + 4 + len).unwrap_or(&[]);
            if code == 0x12 {
                // Connection Parameter Update Request: [min][max][latency][timeout]
                let valid = payload.len() >= 8 && {
                    let (imin, imax, lat, to) = (le16(payload, 0), le16(payload, 2), le16(payload, 4), le16(payload, 6));
                    (6..=3200).contains(&imin)
                        && (6..=3200).contains(&imax)
                        && imin <= imax
                        && lat <= 499
                        && (10..=3200).contains(&to)
                        && u32::from(to) * 4 > (1 + u32::from(lat)) * u32::from(imax)
                };
                // Connection Parameter Update Response: result 0 = accepted, 1 = rejected
                let p = [0x13, ident, 0x02, 0x00, if valid { 0x00 } else { 0x01 }, 0x00];
                let _ = self.send_fixed(handle, CID_LE_SIGNALING, &p);
                if valid {
                    // we are the central: apply it with HCI LE Connection Update (opcode 0x2013)
                    let mut c = handle.to_le_bytes().to_vec();
                    c.extend_from_slice(&payload[..8]);
                    c.extend_from_slice(&[0, 0, 0, 0]); // min/max connection event length: unspecified
                    let _ = self.hci.command_status(0x2013, &c);
                }
            }
            i += 4 + len;
        }
    }

    fn on_signaling(&self, handle: u16, data: &[u8]) {
        let mut i = 0;
        while i + 4 <= data.len() {
            let code = data[i];
            let ident = data[i + 1];
            let len = usize::from(le16(data, i + 2));
            let payload = data.get(i + 4..i + 4 + len).unwrap_or(&[]).to_vec();
            i += 4 + len;
            if is_response(code) {
                self.on_response(code, ident, payload);
                continue;
            }
            match code {
                0x02 => self.on_connection_request(handle, ident, &payload),
                0x04 => self.on_config_request(handle, ident, &payload),
                0x06 => self.on_disconnect_request(handle, ident, &payload),
                0x08 => {
                    // Echo Request: answer with the same data
                    let _ = self.sig_request(handle, 0x09, ident, &payload);
                }
                0x0a => {
                    // Information Request: [info type]; we advertise no optional features
                    let t = [payload.first().copied().unwrap_or(0), payload.get(1).copied().unwrap_or(0)];
                    let _ = self.sig_request(handle, 0x0b, ident, &[t[0], t[1], 0x01, 0x00]);
                }
                _ => {
                    // Command Reject, reason 0x0000 (command not understood)
                    let p = [0x01, ident, 0x02, 0x00, 0x00, 0x00];
                    let _ = self.send_fixed(handle, CID_SIGNALING, &p);
                }
            }
        }
    }

    fn on_response(&self, code: u8, ident: u8, payload: Vec<u8>) {
        let mut st = self.st.lock().unwrap();
        // a "pending" connection response (result 1) is followed by the real one: keep the waiter registered
        let pending = code == 0x03 && payload.len() >= 6 && le16(&payload, 4) == 0x0001;
        let waiter = if pending { st.waiters.get(&ident).cloned() } else { st.waiters.remove(&ident) };
        drop(st);
        if let Some(tx) = waiter {
            let _ = tx.send((code, payload));
        }
    }

    /// Inbound Connection Request: [psm][scid]
    fn on_connection_request(&self, handle: u16, ident: u8, payload: &[u8]) {
        if payload.len() < 4 {
            return;
        }
        let psm = le16(payload, 0);
        let their = le16(payload, 2);
        let listener = self.st.lock().unwrap().listeners.get(&psm).cloned();
        let Some(tx) = listener else {
            // refuse: PSM not supported -> [dcid = 0][scid = theirs][result][status]
            let mut resp = vec![0u8, 0];
            resp.extend_from_slice(&their.to_le_bytes());
            resp.extend_from_slice(&0x0002u16.to_le_bytes());
            resp.extend_from_slice(&[0, 0]);
            let _ = self.sig_request(handle, 0x03, ident, &resp);
            return;
        };
        let (dcid, cfg_ident) = {
            let mut st = self.st.lock().unwrap();
            let dcid = alloc_cid(&mut st);
            st.channels.insert(dcid, Channel { handle, remote_cid: their, psm, mtu: DEFAULT_MTU });
            (dcid, alloc_ident(&mut st))
        };
        let mut resp = dcid.to_le_bytes().to_vec();
        resp.extend_from_slice(&their.to_le_bytes());
        resp.extend_from_slice(&0u16.to_le_bytes()); // result: success
        resp.extend_from_slice(&0u16.to_le_bytes()); // status
        let _ = self.sig_request(handle, 0x03, ident, &resp);
        // our own Configure Request: both directions must be configured before the channel is open
        let mut cfg = their.to_le_bytes().to_vec();
        cfg.extend_from_slice(&0u16.to_le_bytes()); // flags
        cfg.extend_from_slice(&[0x01, 0x02]); // MTU option
        cfg.extend_from_slice(&DEFAULT_MTU.to_le_bytes());
        let _ = self.sig_request(handle, 0x04, cfg_ident, &cfg);
        let _ = tx.send(L2Packet { handle, cid: dcid, psm, data: Vec::new(), closed: false });
    }

    /// Inbound Configure Request: [dcid (ours)][flags][options]
    fn on_config_request(&self, handle: u16, ident: u8, payload: &[u8]) {
        if payload.len() < 4 {
            return;
        }
        let ours = le16(payload, 0);
        let remote = {
            let mut st = self.st.lock().unwrap();
            let Some(c) = st.channels.get_mut(&ours) else {
                return;
            };
            // learn the peer's receive MTU (option type 0x01) - needed for A2DP packet sizing
            let mut i = 4;
            while i + 2 <= payload.len() {
                let t = payload[i] & 0x7f;
                let l = usize::from(payload[i + 1]);
                if t == 0x01 && l >= 2 && i + 4 <= payload.len() {
                    c.mtu = le16(payload, i + 2).max(MIN_MTU);
                }
                i += 2 + l;
            }
            c.remote_cid
        };
        // Configure Response: [scid = the requester's endpoint (its own CID)][flags][result: success]
        let mut resp = remote.to_le_bytes().to_vec();
        resp.extend_from_slice(&0u16.to_le_bytes());
        resp.extend_from_slice(&0u16.to_le_bytes());
        let _ = self.sig_request(handle, 0x05, ident, &resp);
    }

    /// Inbound Disconnect Request: [dcid (ours)][scid (theirs)]
    fn on_disconnect_request(&self, handle: u16, ident: u8, payload: &[u8]) {
        if payload.len() < 4 {
            return;
        }
        let ours = le16(payload, 0);
        // Disconnect Response echoes both CIDs unchanged
        let _ = self.sig_request(handle, 0x07, ident, &payload[..4]);
        let mut st = self.st.lock().unwrap();
        let psm = st.channels.remove(&ours).map_or(0, |c| c.psm);
        if let Some(tx) = st.handlers.remove(&ours) {
            let _ = tx.send(L2Packet { handle, cid: ours, psm, data: Vec::new(), closed: true });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hci::{MockState, MockTransport};

    /// An ACL packet carrying one signaling command, as a remote device would send it.
    fn inbound_signaling(handle: u16, code: u8, ident: u8, payload: &[u8]) -> Vec<u8> {
        let mut sig = vec![code, ident];
        sig.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        sig.extend_from_slice(payload);
        let mut l2 = (sig.len() as u16).to_le_bytes().to_vec();
        l2.extend_from_slice(&CID_SIGNALING.to_le_bytes());
        l2.extend_from_slice(&sig);
        let mut acl = vec![0x02];
        acl.extend_from_slice(&(handle | 0x2000).to_le_bytes()); // PB = 10: start of an L2CAP PDU
        acl.extend_from_slice(&(l2.len() as u16).to_le_bytes());
        acl.extend_from_slice(&l2);
        acl
    }

    /// Wait until the host has sent at least `n` ACL packets.
    fn wait_acl(shared: &Arc<Mutex<MockState>>, n: usize) -> Vec<Vec<u8>> {
        for _ in 0..400 {
            let sent = shared.lock().unwrap().acl_packets();
            if sent.len() >= n {
                return sent;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("host sent fewer than {n} ACL packets");
    }

    // layout of a host ACL packet carrying signaling: 5 (ACL) + 4 (L2CAP) + [code, ident, len(2), payload...]
    const CODE: usize = 9;
    const IDENT: usize = 10;
    const PAYLOAD: usize = 13;

    #[test]
    fn inbound_channel_is_configured_with_the_peers_cid() {
        let mock = MockTransport::new();
        let shared = mock.shared();
        let hci = Arc::new(HciClient::open(0, Box::new(mock)).unwrap());
        let l2 = L2cap::new(hci.clone());
        let (tx, rx) = channel();
        l2.register_listener(0x1234, tx);

        shared.lock().unwrap().inject_event(inbound_signaling(1, 0x02, 7, &[0x34, 0x12, 0x50, 0x00]));
        let chan = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!((chan.psm, chan.cid), (0x1234, 0x0040));

        let sent = wait_acl(&shared, 2);
        // Connection Response: dcid = ours (0x0040), scid = theirs (0x0050), success
        assert_eq!(sent[0][CODE], 0x03);
        assert_eq!(sent[0][IDENT], 7);
        assert_eq!(sent[0][PAYLOAD..PAYLOAD + 8], [0x40, 0x00, 0x50, 0x00, 0, 0, 0, 0]);
        assert_eq!(sent[1][CODE], 0x04); // our Configure Request follows

        // the peer configures its direction: dcid = ours, MTU option 0x009f
        shared.lock().unwrap().inject_event(inbound_signaling(1, 0x04, 9, &[0x40, 0x00, 0, 0, 0x01, 0x02, 0x9f, 0x00]));
        let sent = wait_acl(&shared, 3);
        // Configure Response must carry the REQUESTER's CID (0x0050), not ours
        assert_eq!(sent[2][CODE], 0x05);
        assert_eq!(sent[2][IDENT], 9);
        assert_eq!(sent[2][PAYLOAD..PAYLOAD + 6], [0x50, 0x00, 0, 0, 0, 0]);
        assert_eq!(l2.remote_mtu(0x0040), 0x9f);
        hci.shutdown();
    }

    #[test]
    fn outbound_connect_waits_through_a_pending_response() {
        let mock = MockTransport::new();
        let shared = mock.shared();
        let hci = Arc::new(HciClient::open(0, Box::new(mock)).unwrap());
        let l2 = L2cap::new(hci.clone());
        let l2c = l2.clone();
        let worker = std::thread::spawn(move || l2c.connect(1, 0x0019));

        let sent = wait_acl(&shared, 1);
        assert_eq!(sent[0][CODE], 0x02);
        let ident = sent[0][IDENT];
        assert_eq!(sent[0][PAYLOAD..PAYLOAD + 4], [0x19, 0x00, 0x40, 0x00]); // psm 0x19, our scid 0x40

        // pending (result 1, status 1), then the real answer with dcid 0x0077
        shared.lock().unwrap().inject_event(inbound_signaling(1, 0x03, ident, &[0, 0, 0x40, 0, 1, 0, 1, 0]));
        shared.lock().unwrap().inject_event(inbound_signaling(1, 0x03, ident, &[0x77, 0x00, 0x40, 0, 0, 0, 0, 0]));

        let sent = wait_acl(&shared, 2);
        assert_eq!(sent[1][CODE], 0x04); // Configure Request addressed to the peer's CID
        assert_eq!(sent[1][PAYLOAD..PAYLOAD + 2], [0x77, 0x00]);
        let cfg_ident = sent[1][IDENT];
        shared.lock().unwrap().inject_event(inbound_signaling(1, 0x05, cfg_ident, &[0x40, 0x00, 0, 0, 0, 0]));

        let cid = worker.join().unwrap().unwrap();
        assert_eq!(cid, 0x0040);
        hci.shutdown();
    }
}
