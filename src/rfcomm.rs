use crate::error::{Error, Result};
use crate::l2cap::{L2Packet, L2cap, PSM_RFCOMM};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

// Frame types (P/F bit 0x10 is ORed in where needed)
const SABM: u8 = 0x2f;
const UA: u8 = 0x63;
const DM: u8 = 0x0f;
const DISC: u8 = 0x43;
const UIH: u8 = 0xef;
const PF: u8 = 0x10;

fn addr(dlci: u8, cr: bool) -> u8 { (dlci << 2) | if cr { 0x02 } else { 0x00 } | 0x01 }

fn crc_table() -> [u8; 256] {
    let mut t = [0u8; 256];
    for i in 0..256usize {
        let mut c = i as u8;
        for _ in 0..8 { c = if c & 1 != 0 { (c >> 1) ^ 0x8c } else { c >> 1 }; }
        t[i] = c;
    }
    t
}
fn fcs(bytes: &[u8]) -> u8 {
    static TABLE: std::sync::OnceLock<[u8; 256]> = std::sync::OnceLock::new();
    let t = TABLE.get_or_init(crc_table);
    let mut c = 0xffu8;
    for b in bytes { c = t[(c ^ b) as usize]; }
    0xff - c
}

fn build_frame(dlci: u8, ctrl: u8, payload: &[u8], poll: bool) -> Vec<u8> {
    let a = addr(dlci, true);
    let c = ctrl | if poll { PF } else { 0 };
    let len = payload.len();
    let mut f = vec![a, c];
    if len < 128 { f.push(((len as u8) << 1) | 0x01); }
    else { f.push(((len & 0x7f) as u8) << 1); f.push((len >> 7) as u8); }
    f.extend_from_slice(payload);
    let fcs_len = if (c & 0xef) == UIH { 2 } else { f.len() };
    f.push(fcs(&f[..fcs_len]));
    f
}

struct Parsed { dlci: u8, cr: bool, ctrl: u8, payload: Vec<u8> }

fn parse_frame(d: &[u8]) -> Option<Parsed> {
    if d.len() < 4 { return None; }
    let a = d[0];
    let dlci = a >> 2;
    let cr = a & 0x02 != 0;
    let ctrl = d[1] & 0xef;
    let mut len = ((d[2] as usize) >> 1) as usize;
    let mut off = 3;
    if d[2] & 0x01 == 0 { if d.len() < 4 { return None; } len |= (d[3] as usize) << 7; off = 4; }
    let payload = d.get(off..off + len).unwrap_or(&[]).to_vec();
    Some(Parsed { dlci, cr, ctrl, payload })
}

pub struct RfcommClient {
    pub cid: u16,
    dlci: u8,
    data_rx: Receiver<Vec<u8>>,
    closed: Arc<Mutex<bool>>,
}

impl RfcommClient {
    /// Establish the RFCOMM multiplexer + data DLC to a server channel (HFP/HSP devices).
    pub fn connect(l2: Arc<L2cap>, handle: u16, server_channel: u8) -> Result<Self> {
        let cid = l2.connect(handle, PSM_RFCOMM)?;
        let (tx, data_rx) = channel();
        let (mtx, mrx) = channel::<L2Packet>();
        l2.register_handler(cid, mtx);
        let dlci = (server_channel << 1) | 1; // we initiate the DLC
        let closed = Arc::new(Mutex::new(false));

        // 1. open multiplexer (SABM on DLCI 0)
        l2.send(cid, &build_frame(0, SABM, &[], true))?;
        wait_ctrl(&mrx, |p| p.ctrl == (UA | PF) || p.ctrl == UA, Duration::from_secs(5))?;

        // 2. open data DLC
        l2.send(cid, &build_frame(dlci, SABM, &[], true))?;
        wait_ctrl(&mrx, |p| p.dlci == dlci && (p.ctrl == (UA | PF) || p.ctrl == UA), Duration::from_secs(5))?;

        // 3. MSC modem status
        let msc = [(dlci << 2) | 0x03, 0x8d, 0x01];
        l2.send(cid, &build_frame(0, UIH, &msc, true))?;

        // mux pump: auto-responds to control frames, forwards data
        let l2p = l2.clone();
        let dlci_c = dlci;
        let closed_c = closed.clone();
        std::thread::Builder::new().name("rfcomm".into()).spawn(move || {
            while let Ok(p) = mrx.recv() {
                if p.closed { *closed_c.lock().unwrap() = true; let _ = data_close(&tx); break; }
                let Some(f) = parse_frame(&p.data) else { continue };
                match f.ctrl {
                    UIH if f.dlci == dlci_c => { let _ = tx.send(f.payload); }
                    UIH if f.dlci == 0 && f.cr && !f.payload.is_empty() && (f.payload[0] >> 2) == dlci_c => {
                        // MSC from remote -> answer with response (same V.24 state)
                        let _ = l2p.send(p.cid, &build_frame(0, UIH, &f.payload, false));
                    }
                    DISC if f.dlci == dlci_c => {
                        let _ = l2p.send(p.cid, &build_frame(dlci_c, UA, &[], false));
                        *closed_c.lock().unwrap() = true;
                        let _ = data_close(&tx);
                        break;
                    }
                    DM => { *closed_c.lock().unwrap() = true; let _ = data_close(&tx); break; }
                    _ => {}
                }
            }
        }).ok();

        Ok(RfcommClient { cid, dlci, data_rx, closed })
    }

    pub fn send(&self, l2: &L2cap, data: &[u8]) -> Result<()> {
        if *self.closed.lock().unwrap() { return Err(Error::InvalidState("rfcomm closed".into())); }
        l2.send(self.cid, &build_frame(self.dlci, UIH, data, false))
    }

    pub fn recv_timeout(&self, d: Duration) -> Result<Vec<u8>> {
        self.data_rx.recv_timeout(d).map_err(|_| Error::Timeout("rfcomm data"))
    }

    pub fn is_closed(&self) -> bool { *self.closed.lock().unwrap() }
}

fn data_close(_tx: &Sender<Vec<u8>>) -> std::result::Result<(), ()> { Ok(()) }

fn wait_ctrl(rx: &Receiver<L2Packet>, pred: impl Fn(&Parsed) -> bool, d: Duration) -> Result<()> {
    let deadline = std::time::Instant::now() + d;
    while std::time::Instant::now() < deadline {
        match rx.recv_timeout(deadline - std::time::Instant::now()) {
            Ok(p) if !p.closed => {
                if let Some(f) = parse_frame(&p.data) { if pred(&f) { return Ok(()); } }
                if let Some(f) = parse_frame(&p.data) { if f.ctrl == DM { return Err(Error::ConnectionFailed("rfcomm dm".into())); } }
            }
            _ => return Err(Error::Timeout("rfcomm control frame")),
        }
    }
    Err(Error::Timeout("rfcomm control frame"))
}