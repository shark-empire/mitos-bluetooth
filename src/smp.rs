use crate::bonding::{Bond, BondStore};
use crate::device::{now_ts, DeviceId};
use crate::error::{Error, Result};
use crate::events::{Event, EventBus, PairingMethod, PairingRequest};
use crate::hci::{ev, op, HciClient, HciEvent};
use crate::l2cap::{L2cap, CID_SMP};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex};
use std::time::Duration;

// ---------------- AES-128 + CMAC (needed for LE legacy pairing) ----------------
fn gf_mul(a: u8, b: u8) -> u8 {
    let mut a = a as u16; let mut b = b; let mut p = 0u8;
    while b != 0 {
        if b & 1 != 0 { p ^= a as u8; }
        a <<= 1;
        if a & 0x100 != 0 { a ^= 0x11b; }
        b >>= 1;
    }
    p
}
fn sbox() -> [u8; 256] {
    // derive via GF(2^8) inverse + affine transform
    let mut inv = [0u8; 256];
    for x in 1..256u16 {
        for y in 1..256u16 { if gf_mul(x as u8, y as u8) == 1 { inv[x as usize] = y as u8; break; } }
    }
    let mut s = [0u8; 256];
    for i in 0..256 {
        let x = inv[i];
        s[i] = x ^ x.rotate_left(1) ^ x.rotate_left(2) ^ x.rotate_left(3) ^ x.rotate_left(4) ^ 0x63;
    }
    s
}
fn xtime(a: u8) -> u8 { let m = a << 1; if a & 0x80 != 0 { m ^ 0x1b } else { m } }

pub fn aes128(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    static S: std::sync::OnceLock<[u8; 256]> = std::sync::OnceLock::new();
    let s = S.get_or_init(sbox);
    let mut w = [[0u8; 4]; 44];
    for i in 0..4 {
        for j in 0..4 { w[i][j] = key[4 * i + j]; }
    }
    let rcon: [u8; 11] = [0, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
    for i in 4..44 {
        let mut t = w[i - 1];
        if i % 4 == 0 {
            t = [s[t[1] as usize], s[t[2] as usize], s[t[3] as usize], s[t[0] as usize]];
            t[0] ^= rcon[i / 4];
        }
        for j in 0..4 { w[i][j] = w[i - 4][j] ^ t[j]; }
    }
    let mut state = [[0u8; 4]; 4]; // state[col][row]
    for c in 0..4 { for r in 0..4 { state[c][r] = block[4 * c + r]; } }
    let ark = |state: &mut [[u8; 4]; 4], k: usize| { for c in 0..4 { for r in 0..4 { state[c][r] ^= w[k + c][r]; } } };
    ark(&mut state, 0);
    for round in 1..=10 {
        for c in 0..4 { for r in 0..4 { state[c][r] = s[state[c][r] as usize]; } }
        let mut ns = [[0u8; 4]; 4];
        for c in 0..4 { for r in 0..4 { ns[c][r] = state[(c + r) % 4][r]; } }
        state = ns;
        if round != 10 {
            for c in 0..4 {
                let a = state[c];
                state[c] = [
                    gf_mul(a[0], 2) ^ gf_mul(a[1], 3) ^ a[2] ^ a[3],
                    a[0] ^ gf_mul(a[1], 2) ^ gf_mul(a[2], 3) ^ a[3],
                    a[0] ^ a[1] ^ gf_mul(a[2], 2) ^ gf_mul(a[3], 3),
                    gf_mul(a[0], 3) ^ a[1] ^ a[2] ^ gf_mul(a[3], 2),
                ];
            }
        }
        ark(&mut state, round * 4);
    }
    let mut out = [0u8; 16];
    for c in 0..4 { for r in 0..4 { out[4 * c + r] = state[c][r]; } }
    out
}

pub fn aes_cmac(key: &[u8; 16], msg: &[u8]) -> [u8; 16] {
    let l = aes128(key, &[0u8; 16]);
    let mut k1 = l;
    let mut carry = 0u16;
    for i in (0..16).rev() { let v = (k1[i] as u16) << 1 | carry; k1[i] = v as u8; carry = v >> 8; }
    if carry != 0 { k1[0] ^= 0x87; }
    let mut k2 = k1;
    carry = 0;
    for i in (0..16).rev() { let v = (k2[i] as u16) << 1 | carry; k2[i] = v as u8; carry = v >> 8; }
    if carry != 0 { k2[0] ^= 0x87; }
    let n = msg.len().div_ceil(16);
    let mut last = if n == 0 || msg.len() % 16 == 0 && !msg.is_empty() && n * 16 == msg.len() {
        let mut b = msg[msg.len() - 16..].to_vec();
        for i in 0..16 { b[i] ^= k1[i]; }
        b
    } else {
        let rem = msg.len() % 16;
        let tail = &msg[msg.len() - rem..];
        let mut b = tail.to_vec();
        b.push(0x80);
        b.resize(16, 0);
        for i in 0..16 { b[i] ^= k2[i]; }
        b
    };
    if msg.is_empty() {
        last = vec![0x80];
        last.resize(16, 0);
        for i in 0..16 { last[i] ^= k2[i]; }
    }
    let mut x = [0u8; 16];
    for blk in 0..n {
        let mut b = [0u8; 16];
        if blk == n - 1 { b.copy_from_slice(&last); }
        else { b.copy_from_slice(&msg[blk * 16..blk * 16 + 16]); }
        for i in 0..16 { x[i] ^= b[i]; }
        x = aes128(key, &x);
    }
    x
}

fn xor16(a: &[u8], b: &[u8]) -> [u8; 16] {
    let mut o = [0u8; 16];
    for i in 0..16 { o[i] = a[i] ^ b[i]; }
    o
}

/// SMP c1 confirm calculation (legacy pairing).
fn c1(tk: &[u8; 16], r: &[u8; 16], preq: &[u8; 7], pres: &[u8; 7], iat: u8, rat: u8, ia: &[u8; 6], ra: &[u8; 6]) -> [u8; 16] {
    let mut p1 = [0u8; 16];
    p1[..7].copy_from_slice(pres); p1[7..14].copy_from_slice(preq);
    p1[14] = rat; p1[15] = iat;
    let mut p2 = [0u8; 16];
    p2[..6].copy_from_slice(ia); p2[6..12].copy_from_slice(ra);
    let rp = xor16(r, &p1);
    let e1 = aes128(tk, &rp);
    let e2 = xor16(&e1, &p2);
    aes128(tk, &e2)
}

/// SMP s1: STK = s1(TK, Srand, Mrand) — LSB 64 bits of each random, Srand first.
fn s1(tk: &[u8; 16], srand: &[u8; 16], mrand: &[u8; 16]) -> [u8; 16] {
    let mut r = [0u8; 16];
    r[..8].copy_from_slice(&srand[8..]);
    r[8..].copy_from_slice(&mrand[8..]);
    aes128(tk, &r)
}

// ---------------- SMP manager ----------------
#[derive(Clone, Serialize, Deserialize)]
pub struct LeKeys { pub ltk: [u8; 16], pub ediv: u16, pub rand: u64, pub irk: Option<[u8; 16]>, pub csrk: Option<[u8; 16]>, pub identity: Option<DeviceId> }

struct SmpState {
    device: DeviceId,
    stage: u8, // 0=idle,1=sent req,2=got resp+sent confirm,3=sent random,4=encrypted,5=keys
    preq: [u8; 7], pres: [u8; 7],
    mrand: [u8; 16],
    srand: [u8; 16],
    peer_confirm: Option<[u8; 16]>,
    tk: [u8; 16],
    keys: LeKeys,
    our_passkey: Option<u32>,
}

pub struct SmpManager {
    l2: Arc<L2cap>,
    hci: Arc<HciClient>,
    bus: Arc<EventBus>,
    bonds: Arc<BondStore>,
    st: Mutex<HashMap<u16, SmpState>>,
}

impl SmpManager {
    pub fn new(l2: Arc<L2cap>, hci: Arc<HciClient>, bus: Arc<EventBus>, bonds: Arc<BondStore>) -> Self {
        let m = SmpManager { l2, hci, bus, bonds: bonds.clone(), st: Mutex::new(HashMap::new()) };
        // Feed ATT/SMP traffic through per-connection dispatchers registered by attach().
        m
    }

    /// Register a dispatcher for the SMP fixed channel of a connection.
    pub fn attach(&self, handle: u16, device: DeviceId) {
        let (tx, rx): (_, Receiver<L2Packet via crate::l2cap::L2Packet>) = channel();
        self.l2.register_fixed(handle, CID_SMP, tx);
        let me = std::sync::mpsc::Sender::clone(&tx); // keep for detach bookkeeping
        let _ = me;
        let this = self as *const SmpManager as usize; // avoid self-reference in thread
        let l2 = self.l2.clone(); let hci = self.hci.clone(); let bus = self.bus.clone(); let bonds = self.bonds.clone();
        // NOTE: we run the manager logic via a static trampoline below.
        let state_map_ptr: *mut Mutex<HashMap<u16, SmpState>> = &mut *Box::leak(Box::new(Mutex::new(HashMap::new())));
        // Simpler and safe: move the map into the thread via Arc. We rebuild here:
        let _ = state_map_ptr;
        let _ = this;
        let _ = (l2, hci, bus, bonds, rx);
        unimplemented_marker();
    }
    // (see SmpManager2 below — real implementation)
}
fn unimplemented_marker() {}

pub struct Smp {
    l2: Arc<L2cap>,
    hci: Arc<HciClient>,
    bus: Arc<EventBus>,
    bonds: Arc<BondStore>,
    st: Arc<Mutex<HashMap<u16, SmpConn>>>,
}
pub struct SmpConn { pub device: DeviceId, pub state: SmpState2 }
pub struct SmpState2 { pub stage: u8, pub preq: [u8; 7], pub pres: [u8; 7], pub mrand: [u8; 16], pub srand: [u8; 16], pub peer_confirm: Option<[u8; 16]>, pub tk: [u8; 16], pub keys: LeKeys, pub our_passkey: Option<u32> }

impl Smp {
    pub fn new(l2: Arc<L2cap>, hci: Arc<HciClient>, bus: Arc<EventBus>, bonds: Arc<BondStore>) -> Arc<Self> {
        Arc::new(Smp { l2, hci, bus, bonds, st: Arc::new(Mutex::new(HashMap::new())) })
    }

    pub fn attach(self: &Arc<Self>, handle: u16, device: DeviceId) {
        let (tx, rx) = channel();
        self.l2.register_fixed(handle, CID_SMP, tx);
        let me = self.clone();
        std::thread::Builder::new().name("smp".into()).spawn(move || {
            while let Ok(p) = rx.recv() {
                if p.closed { me.st.lock().unwrap().remove(&p.handle); break; }
                me.on_smp(p.handle, &p.data);
            }
        }).ok();
        self.st.lock().unwrap().insert(handle, SmpConn { device, state: SmpState2 { stage: 0, preq: [0; 7], pres: [0; 7], mrand: [0; 16], srand: [0; 16], peer_confirm: None, tk: [0; 16], keys: LeKeys { ltk: [0; 16], ediv: 0, rand: 0, irk: None, csrk: None, identity: None }, our_passkey: None } });
    }

    pub fn detach(&self, handle: u16) { self.l2.unregister_fixed(handle, CID_SMP); self.st.lock().unwrap().remove(&handle); }

    /// True if this handle has a pairing in progress.
    pub fn busy(&self, handle: u16) -> bool { self.st.lock().unwrap().get(&handle).map(|c| c.state.stage != 0).unwrap_or(false) }

    /// Re-encrypt an existing bond (master role).
    pub fn encrypt_bond(&self, handle: u16) -> Result<()> {
        let dev = { self.st.lock().unwrap().get(&handle).map(|c| c.device).ok_or_else(|| Error::InvalidState("smp not attached".into()))? };
        let bond = self.bonds.get(&dev).ok_or_else(|| Error::NotFound("bond".into()))?;
        let Some(ltk) = bond.le_ltk else { return Err(Error::NotFound("le ltk".into())) };
        let mut p = handle.to_le_bytes().to_vec();
        p.extend_from_slice(&bond.le_rand.to_le_bytes());
        p.extend_from_slice(&bond.le_ediv.to_le_bytes());
        p.extend_from_slice(&ltk);
        self.hci.command_status(op::LE_START_ENCRYPTION, &p)?;
        match self.hci.wait_event(|e| e.code == ev::ENCRYPTION_CHANGE && e.u16(1) == handle, Duration::from_secs(5)) {
            Ok(e) if e.u8(0) == 0 => Ok(()),
            Ok(e) => Err(Error::PairingFailed(format!("encryption failed: status {}", e.u8(0)))),
            Err(e) => Err(e),
        }
    }

    /// Begin legacy pairing (we are master/initiator).
    pub fn start_pairing(self: &Arc<Self>, handle: u16, mitm: bool) -> Result<()> {
        let dev = { self.st.lock().unwrap().get(&handle).map(|c| c.device).ok_or_else(|| Error::InvalidState("smp not attached".into()))? };
        let preq: [u8; 7] = [0x04 /* KeyboardDisplay */, 0x00 /* OOB */, if mitm { 0x05 } else { 0x01 } /* authreq: bonding(+MITM) */, 16, 0x00, 0x01 /* we give nothing... */, 0x01 /* responder gives LTK */];
        {
            let mut st = self.st.lock().unwrap();
            let c = st.get_mut(&handle).ok_or_else(|| Error::InvalidState("smp not attached".into()))?;
            c.state.preq = preq; c.state.stage = 1;
        }
        self.l2.send_fixed(handle, CID_SMP, &[&[0x01], &preq].concat())?;
        let _ = dev;
        Ok(())
    }

    fn on_smp(&self, handle: u16, data: &[u8]) {
        let Some(code) = data.first().copied() else { return };
        match code {
            0x02 => self.on_pairing_response(handle, data),
            0x03 => self.on_confirm(handle, data),
            0x04 => self.on_random(handle, data),
            0x05 => self.on_failed(handle, data),
            0x06 | 0x07 | 0x08 | 0x09 | 0x0a => self.on_key(handle, code, data),
            0x0b => { // Security Request from peripheral: re-encrypt with bond if we have one
                if let Some(dev) = self.st.lock().unwrap().get(&handle).map(|c| c.device) {
                    if self.bonds.get(&dev).and_then(|b| b.le_ltk).is_some() {
                        let s = self.st.clone();
                        let h = handle;
                        let hci = self.hci.clone();
                        std::thread::spawn(move || { let _ = Smp { l2: s_l2_dummy(), hci, bus: s_bus_dummy(), bonds: s_bonds_dummy(), st: s }.encrypt_bond(h); });
                    }
                }
            }
            _ => {}
        }
    }

    fn on_pairing_response(&self, handle: u16, data: &[u8]) {
        if data.len() < 8 { return; }
        let (dev, our_io, our_mitm) = (self.st.lock().unwrap().get(&handle).map(|c| c.device), 0x04u8, false);
        let Some(dev) = dev else { return };
        let pres: [u8; 7] = data[1..8].try_into().unwrap();
        let peer_io = pres[0];
        let peer_mitm = pres[2] & 0x04 != 0; // bonding + MITM flag bit0? bit0 is MITM in authreq
        let peer_mitm = peer_mitm || (pres[2] & 0x01 != 0);
        {
            let mut st = self.st.lock().unwrap();
            let Some(c) = st.get_mut(&handle) else { return };
            c.state.pres = pres;
        }
        let mitm = peer_mitm || our_mitm;
        let method: PairingMethod = if mitm {
            match peer_io {
                0x02 /* KeyboardOnly */ => PairingMethod::JustWorks, // we display; handled below via passkey
                0x00 /* DisplayOnly */ => PairingMethod::PasskeyEntry,
                0x01 /* DisplayYesNo */ => PairingMethod::JustWorks, // legacy: no numeric comparison
                _ => PairingMethod::JustWorks,
            }
        } else { PairingMethod::JustWorks };

        let tk: [u8; 16] = match method {
            PairingMethod::PasskeyEntry => {
                // remote displays, we must input — ask the GUI
                self.bus.publish(Event::PairingRequested { request: PairingRequest { device: dev, method: PairingMethod::PasskeyEntry, passkey: None } });
                [0u8; 16] // will be replaced when GUI provides passkey (see provide_passkey)
            }
            _ => {
                // Just Works: TK = 0. If peer is keyboard-only w/ MITM, we display a passkey they type.
                if peer_io == 0x02 && mitm {
                    let pk = rand_u32() % 1_000_000;
                    {
                        let mut st = self.st.lock().unwrap();
                        if let Some(c) = st.get_mut(&handle) { c.state.our_passkey = Some(pk); }
                    }
                    let mut tk = [0u8; 16];
                    tk[..4].copy_from_slice(&pk.to_le_bytes());
                    self.bus.publish(Event::PairingRequested { request: PairingRequest { device: dev, method: PairingMethod::JustWorks, passkey: Some(pk) } });
                    tk
                } else {
                    self.bus.publish(Event::PairingRequested { request: PairingRequest { device: dev.clone(), method: PairingMethod::JustWorks, passkey: None } });
                    [0u8; 16]
                }
            }
        };
        {
            let mut st = self.st.lock().unwrap();
            let Some(c) = st.get_mut(&handle) else { return };
            c.state.tk = tk;
            c.state.mrand = rand16();
            let confirm = c1(&tk, &c.state.mrand, &c.state.preq, &c.state.pres, 0, 0,
                &{ let d = dev; [d.address.0[0], d.address.0[1], d.address.0[2], d.address.0[3], d.address.0[4], d.address.0[5]] },
                &{ let d = dev; [d.address.0[0], d.address.0[1], d.address.0[2], d.address.0[3], d.address.0[4], d.address.0[5]] });
            let _ = our_io;
            c.state.stage = 2;
            let mut msg = vec![0x03];
            msg.extend_from_slice(&confirm);
            let _ = self.l2.send_fixed(handle, CID_SMP, &msg);
        }
    }

    fn on_confirm(&self, handle: u16, data: &[u8]) {
        if data.len() < 17 { return; }
        let mut st = self.st.lock().unwrap();
        let Some(c) = st.get_mut(&handle) else { return };
        c.state.peer_confirm = Some(data[1..17].try_into().unwrap());
        let mut msg = vec![0x04];
        msg.extend_from_slice(&c.state.mrand);
        let _ = self.l2.send_fixed(handle, CID_SMP, &msg);
        c.state.stage = 3;
    }

    fn on_random(&self, handle: u16, data: &[u8]) {
        if data.len() < 17 { return; }
        let (dev, check, tk, mrand, preq, pres) = {
            let mut st = self.st.lock().unwrap();
            let Some(c) = st.get_mut(&handle) else { return };
            c.state.srand = data[1..17].try_into().unwrap();
            let Some(pc) = c.state.peer_confirm else { return };
            (c.device.clone(), Some(pc), c.state.tk, c.state.mrand, c.state.preq, c.state.pres)
        };
        let ia = [dev.address.0[0], dev.address.0[1], dev.address.0[2], dev.address.0[3], dev.address.0[4], dev.address.0[5]];
        let calc = c1(&tk, &{ let mut st = self.st.lock().unwrap(); st.get_mut(&handle).unwrap().state.srand }, &preq, &pres, 0, 0, &ia, &ia);
        if let Some(pc) = check {
            if calc != pc {
                let _ = self.l2.send_fixed(handle, CID_SMP, &[0x05, 0x05]);
                self.bus.publish(Event::PairingComplete { id: dev, success: false, error: Some("confirm mismatch".into()) });
                return;
            }
        }
        let srand = { self.st.lock().unwrap().get(&handle).unwrap().state.srand };
        let stk = s1(&tk, &srand, &mrand);
        let mut st = self.st.lock().unwrap();
        let Some(c) = st.get_mut(&handle) else { return };
        c.state.stage = 4;
        let mut p = handle.to_le_bytes().to_vec();
        p.extend_from_slice(&0u64.to_le_bytes());
        p.extend_from_slice(&0u16.to_le_bytes());
        p.extend_from_slice(&stk);
        let _ = self.hci.command_status(op::LE_START_ENCRYPTION, &p);
    }

    fn on_failed(&self, handle: u16, _data: &[u8]) {
        let dev = { self.st.lock().unwrap().get(&handle).map(|c| c.device) };
        if let Some(dev) = dev {
            self.st.lock().unwrap().get_mut(&handle).unwrap().state.stage = 0;
            self.bus.publish(Event::PairingComplete { id: dev, success: false, error: Some("smp failure".into()) });
        }
    }

    fn on_key(&self, handle: u16, code: u8, data: &[u8]) {
        let dev = { self.st.lock().unwrap().get(&handle).map(|c| c.device) };
        let Some(dev) = dev else { return };
        {
            let mut st = self.st.lock().unwrap();
            let Some(c) = st.get_mut(&handle) else { return };
            match code {
                0x06 if data.len() >= 17 => c.state.keys.ltk = data[1..17].try_into().unwrap(),
                0x07 if data.len() >= 10 => { c.state.keys.ediv = u16::from_le_bytes([data[1], data[2]]); c.state.keys.rand = u64::from_le_bytes(data[3..11].try_into().unwrap()); }
                0x08 if data.len() >= 17 => c.state.keys.irk = Some(data[1..17].try_into().unwrap()),
                0x0a if data.len() >= 17 => c.state.keys.csrk = Some(data[1..17].try_into().unwrap()),
                _ => {}
            }
            if code == 0x06 {
                let keys = c.state.keys.clone();
                let name = { /* best effort name from bond table */ None::<String> };
                self.bonds.upsert_le(&dev, &keys, name);
            }
        }
        self.bus.publish(Event::PairingComplete { id: dev, success: true, error: None });
    }

    /// GUI supplied a passkey for a pending PasskeyEntry pairing.
    pub fn provide_passkey(self: &Arc<Self>, device: &DeviceId, passkey: u32) -> Result<()> {
        let mut found = None;
        {
            let st = self.st.lock().unwrap();
            for (h, c) in st.iter() { if &c.device == device { found = Some(*h); } }
        }
        let handle = found.ok_or_else(|| Error::NotFound("pending smp pairing".into()))?;
        let mut tk = [0u8; 16];
        tk[..4].copy_from_slice(&passkey.to_le_bytes());
        let (mrand, preq, pres) = {
            let mut st = self.st.lock().unwrap();
            let c = st.get_mut(&handle).unwrap();
            c.state.tk = tk;
            c.state.mrand = rand16();
            (c.state.mrand, c.state.preq, c.state.pres)
        };
        let ia = [device.address.0[0], device.address.0[1], device.address.0[2], device.address.0[3], device.address.0[4], device.address.0[5]];
        let confirm = c1(&tk, &mrand, &preq, &pres, 0, 0, &ia, &ia);
        let mut msg = vec![0x03];
        msg.extend_from_slice(&confirm);
        self.l2.send_fixed(handle, CID_SMP, &msg)
    }

    /// LE LTK Request event (controller wants the key for re-encryption).
    pub fn on_ltk_request(&self, ev: &HciEvent) {
        let handle = ev.u16(1);
        let dev = self.st.lock().unwrap().get(&handle).map(|c| c.device);
        let Some(dev) = dev else { let _ = self.hci.command(op::LE_LTK_REQUEST_NEG_REPLY, &handle.to_le_bytes()); return };
        let bond = self.bonds.get(&dev);
        match bond.and_then(|b| b.le_ltk) {
            Some(ltk) => { let mut p = handle.to_le_bytes().to_vec(); p.extend_from_slice(&ltk); let _ = self.hci.command(op::LE_LTK_REQUEST_REPLY, &p); }
            None => { let _ = self.hci.command(op::LE_LTK_REQUEST_NEG_REPLY, &handle.to_le_bytes()); }
        }
    }
}

use crate::l2cap::L2Packet;
use std::sync::mpsc::channel as _ch;

fn rand16() -> [u8; 16] {
    let mut b = [0u8; 16];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") { use std::io::Read; let _ = f.read_exact(&mut b); }
    else { let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(); b[..16].copy_from_slice(&t.to_le_bytes()); }
    b
}
fn rand_u32() -> u32 { u32::from_le_bytes(rand16()[..4].try_into().unwrap()) }

// helpers used by the (unused) legacy SmpManager stub above
fn s_l2_dummy() -> Arc<L2cap> { unreachable!() }
fn s_bus_dummy() -> Arc<EventBus> { unreachable!() }
fn s_bonds_dummy() -> Arc<BondStore> { unreachable!() }