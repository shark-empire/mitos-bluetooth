use crate::bonding::BondStore;
use crate::device::{Address, AddressType, DeviceId};
use crate::error::{hci_status_text, Error, Result};
use crate::events::{Event, EventBus, PairingMethod, PairingRequest};
use crate::hci::{ev, op, HciClient, HciEvent};
use crate::l2cap::{L2cap, CID_SMP};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::time::Duration;

// ---------------- AES-128 + CMAC (LE legacy pairing, and the building block for Secure Connections) ----------------
fn gf_mul(a: u8, b: u8) -> u8 {
    let mut a = a as u16;
    let mut b = b;
    let mut p = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a as u8;
        }
        a <<= 1;
        if a & 0x100 != 0 {
            a ^= 0x11b;
        }
        b >>= 1;
    }
    p
}

fn sbox() -> [u8; 256] {
    // derive via GF(2^8) inverse + affine transform
    let mut inv = [0u8; 256];
    for x in 1..256u16 {
        for y in 1..256u16 {
            if gf_mul(x as u8, y as u8) == 1 {
                inv[x as usize] = y as u8;
                break;
            }
        }
    }
    let mut s = [0u8; 256];
    for i in 0..256 {
        let x = inv[i];
        s[i] = x ^ x.rotate_left(1) ^ x.rotate_left(2) ^ x.rotate_left(3) ^ x.rotate_left(4) ^ 0x63;
    }
    s
}

pub fn aes128(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    static S: std::sync::OnceLock<[u8; 256]> = std::sync::OnceLock::new();
    let s = S.get_or_init(sbox);
    let mut w = [[0u8; 4]; 44];
    for i in 0..4 {
        for j in 0..4 {
            w[i][j] = key[4 * i + j];
        }
    }
    let rcon: [u8; 11] = [0, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
    for i in 4..44 {
        let mut t = w[i - 1];
        if i % 4 == 0 {
            t = [s[t[1] as usize], s[t[2] as usize], s[t[3] as usize], s[t[0] as usize]];
            t[0] ^= rcon[i / 4];
        }
        for j in 0..4 {
            w[i][j] = w[i - 4][j] ^ t[j];
        }
    }
    let mut state = [[0u8; 4]; 4]; // state[col][row]
    for c in 0..4 {
        for r in 0..4 {
            state[c][r] = block[4 * c + r];
        }
    }
    let ark = |state: &mut [[u8; 4]; 4], k: usize| {
        for c in 0..4 {
            for r in 0..4 {
                state[c][r] ^= w[k + c][r];
            }
        }
    };
    ark(&mut state, 0);
    for round in 1..=10 {
        for c in 0..4 {
            for r in 0..4 {
                state[c][r] = s[state[c][r] as usize];
            }
        }
        let mut shifted = [[0u8; 4]; 4];
        for c in 0..4 {
            for r in 0..4 {
                shifted[c][r] = state[(c + r) % 4][r];
            }
        }
        state = shifted;
        if round != 10 {
            for col in state.iter_mut() {
                let a = *col;
                *col = [
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
    for c in 0..4 {
        for r in 0..4 {
            out[4 * c + r] = state[c][r];
        }
    }
    out
}

/// Left shift by one bit (big-endian block), folding in the CMAC constant Rb = 0x87 when a bit falls off.
fn cmac_double(b: &[u8; 16]) -> [u8; 16] {
    let mut o = [0u8; 16];
    let mut carry = 0u8;
    for i in (0..16).rev() {
        o[i] = (b[i] << 1) | carry;
        carry = b[i] >> 7;
    }
    if b[0] & 0x80 != 0 {
        o[15] ^= 0x87;
    }
    o
}

/// AES-CMAC (RFC 4493).
pub fn aes_cmac(key: &[u8; 16], msg: &[u8]) -> [u8; 16] {
    let l = aes128(key, &[0u8; 16]);
    let k1 = cmac_double(&l);
    let k2 = cmac_double(&k1);
    let blocks = msg.len().div_ceil(16).max(1);
    let complete = !msg.is_empty() && msg.len().is_multiple_of(16);
    let mut x = [0u8; 16];
    for chunk in msg.chunks(16).take(blocks - 1) {
        for (xi, mi) in x.iter_mut().zip(chunk) {
            *xi ^= mi;
        }
        x = aes128(key, &x);
    }
    let tail = msg.get((blocks - 1) * 16..).unwrap_or(&[]);
    let mut last = [0u8; 16];
    last[..tail.len()].copy_from_slice(tail);
    let subkey = if complete {
        &k1
    } else {
        last[tail.len()] = 0x80;
        &k2
    };
    for (li, ki) in last.iter_mut().zip(subkey) {
        *li ^= ki;
    }
    for (xi, li) in x.iter_mut().zip(&last) {
        *xi ^= li;
    }
    aes128(key, &x)
}

fn xor16(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut o = [0u8; 16];
    for (i, slot) in o.iter_mut().enumerate() {
        *slot = a[i] ^ b[i];
    }
    o
}

/// SMP "e": AES-128 on little-endian byte arrays (the order values travel in over the air). The AES block
/// and key are big-endian, so both inputs and the output are byte-reversed (Core Vol 3 Part H, 2.2.1).
fn e(key: &[u8; 16], plain: &[u8; 16]) -> [u8; 16] {
    let mut k = *key;
    k.reverse();
    let mut p = *plain;
    p.reverse();
    let mut out = aes128(&k, &p);
    out.reverse();
    out
}

/// Address types and addresses that enter the legacy confirm value (initiator = us).
struct PairAddrs {
    iat: u8,
    ia: [u8; 6],
    rat: u8,
    ra: [u8; 6],
}

/// c1 confirm value (Core Vol 3 Part H, 2.2.3). `preq`/`pres` are the complete 7-byte pairing PDUs, opcode first.
fn c1(tk: &[u8; 16], r: &[u8; 16], preq: &[u8; 7], pres: &[u8; 7], a: &PairAddrs) -> [u8; 16] {
    let mut p1 = [0u8; 16];
    p1[0] = a.iat;
    p1[1] = a.rat;
    p1[2..9].copy_from_slice(preq);
    p1[9..16].copy_from_slice(pres);
    let mut p2 = [0u8; 16];
    p2[0..6].copy_from_slice(&a.ra);
    p2[6..12].copy_from_slice(&a.ia);
    e(tk, &xor16(&e(tk, &xor16(r, &p1)), &p2))
}

/// s1 key generation (Core Vol 3 Part H, 2.2.4): STK = s1(TK, Srand, Mrand) uses the low 64 bits of each, Mrand lowest.
fn s1(tk: &[u8; 16], srand: &[u8; 16], mrand: &[u8; 16]) -> [u8; 16] {
    let mut r = [0u8; 16];
    r[..8].copy_from_slice(&mrand[..8]);
    r[8..].copy_from_slice(&srand[..8]);
    e(tk, &r)
}

fn rand16() -> Result<[u8; 16]> {
    let mut b = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut b)?;
    Ok(b)
}

fn rand_u32() -> Result<u32> {
    let b = rand16()?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// `N` bytes at offset `from`, if the PDU is long enough.
fn arr<const N: usize>(d: &[u8], from: usize) -> Option<[u8; N]> {
    d.get(from..from + N).and_then(|s| <[u8; N]>::try_from(s).ok())
}

// ---------------- SMP manager (LE legacy pairing, we are the initiator/central) ----------------
const IO_KEYBOARD_DISPLAY: u8 = 0x04;
const AUTH_BONDING: u8 = 0x01;
const AUTH_MITM: u8 = 0x04;
const KEYDIST_ENC: u8 = 0x01;
const KEYDIST_ID: u8 = 0x02;
const KEYDIST_SIGN: u8 = 0x04;
const REASON_CONFIRM_FAILED: u8 = 0x04;
const REASON_ENC_KEY_SIZE: u8 = 0x06;
const REASON_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const REASON_UNSPECIFIED: u8 = 0x08;
const REASON_INVALID_PARAMETERS: u8 = 0x0a;

#[derive(Clone, Serialize, Deserialize)]
pub struct LeKeys {
    pub ltk: [u8; 16],
    pub ediv: u16,
    pub rand: u64,
    pub irk: Option<[u8; 16]>,
    pub csrk: Option<[u8; 16]>,
    pub identity: Option<DeviceId>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Idle,
    Requested,
    WaitPasskey,
    ConfirmSent,
    RandomSent,
    Encrypting,
    KeyDist,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Model {
    JustWorks,
    DisplayHere,
    EnterHere,
}

/// Legacy association model (Core Vol 3 Part H, 2.3.5.1) for us as a KeyboardDisplay initiator.
fn model_for(peer_io: u8, mitm: bool) -> Model {
    if !mitm {
        return Model::JustWorks;
    }
    match peer_io {
        0x03 => Model::JustWorks,        // NoInputNoOutput: nothing to exchange
        0x00 | 0x01 => Model::EnterHere, // the peer shows a passkey: we type it
        _ => Model::DisplayHere,         // KeyboardOnly / KeyboardDisplay: we show it, the peer types it
    }
}

struct SmpConn {
    device: DeviceId,
    stage: Stage,
    preq: [u8; 7],
    pres: [u8; 7],
    tk: [u8; 16],
    mrand: [u8; 16],
    peer_confirm: [u8; 16],
    keys: LeKeys,
    encrypted: bool,
    /// Key-distribution PDUs the peer promised (bit n = opcode 0x06 + n) and the ones that arrived.
    expected: u8,
    received: u8,
}

impl SmpConn {
    fn new(device: DeviceId) -> Self {
        SmpConn {
            device,
            stage: Stage::Idle,
            preq: [0; 7],
            pres: [0; 7],
            tk: [0; 16],
            mrand: [0; 16],
            peer_confirm: [0; 16],
            keys: LeKeys { ltk: [0; 16], ediv: 0, rand: 0, irk: None, csrk: None, identity: None },
            encrypted: false,
            expected: 0,
            received: 0,
        }
    }

    /// Back to idle, wiping every secret of the finished (or failed) exchange.
    fn reset(&mut self) {
        *self = SmpConn::new(self.device);
    }
}

pub struct Smp {
    l2: Arc<L2cap>,
    hci: Arc<HciClient>,
    bus: Arc<EventBus>,
    bonds: Arc<BondStore>,
    /// Our controller's public BD_ADDR (the initiator address in the confirm calculation).
    own: Address,
    st: Mutex<HashMap<u16, SmpConn>>,
}

impl Smp {
    pub fn new(
        l2: Arc<L2cap>,
        hci: Arc<HciClient>,
        bus: Arc<EventBus>,
        bonds: Arc<BondStore>,
        own: Address,
    ) -> Arc<Self> {
        Arc::new(Smp { l2, hci, bus, bonds, own, st: Mutex::new(HashMap::new()) })
    }

    pub fn attach(self: &Arc<Self>, handle: u16, device: DeviceId) {
        {
            let mut st = self.st.lock().unwrap();
            if st.contains_key(&handle) {
                return;
            }
            st.insert(handle, SmpConn::new(device));
        }
        let (tx, rx) = channel();
        self.l2.register_fixed(handle, CID_SMP, tx);
        // the worker holds only a Weak reference: it ends with the connection or when the stack is dropped
        let weak = Arc::downgrade(self);
        std::thread::Builder::new()
            .name("smp".into())
            .spawn(move || {
                while let Ok(p) = rx.recv() {
                    if p.closed {
                        break;
                    }
                    match weak.upgrade() {
                        Some(me) => me.on_smp(p.handle, &p.data),
                        None => break,
                    }
                }
            })
            .ok();
    }

    pub fn detach(&self, handle: u16) {
        self.l2.unregister_fixed(handle, CID_SMP);
        self.st.lock().unwrap().remove(&handle);
    }

    fn device_of(&self, handle: u16) -> Option<DeviceId> {
        self.st.lock().unwrap().get(&handle).map(|c| c.device)
    }

    /// True if this handle has a pairing in progress.
    pub fn busy(&self, handle: u16) -> bool {
        self.st.lock().unwrap().get(&handle).is_some_and(|c| c.stage != Stage::Idle)
    }

    fn addrs_for(&self, peer: &DeviceId) -> PairAddrs {
        PairAddrs {
            iat: 0, // the controller's own address is its public BD_ADDR
            ia: self.own.0,
            rat: u8::from(peer.address_type == AddressType::LeRandom),
            ra: peer.address.0,
        }
    }

    /// End an exchange: optionally tell the peer (Pairing Failed), wipe the state, tell the application.
    fn fail(&self, handle: u16, reason: Option<u8>, msg: &str) {
        let device = {
            let mut st = self.st.lock().unwrap();
            match st.get_mut(&handle) {
                Some(c) if c.stage != Stage::Idle => {
                    let d = c.device;
                    c.reset();
                    Some(d)
                }
                _ => None,
            }
        };
        if let Some(device) = device {
            if let Some(code) = reason {
                let _ = self.l2.send_fixed(handle, CID_SMP, &[0x05, code]);
            }
            self.bus.publish(Event::PairingComplete { id: device, success: false, error: Some(msg.to_string()) });
        }
    }

    /// Give up on a pairing that did not finish in time (the peer is told).
    pub fn cancel(&self, handle: u16) {
        self.fail(handle, Some(REASON_UNSPECIFIED), "pairing cancelled");
    }

    pub fn cancel_device(&self, device: &DeviceId) {
        let handle = self
            .st
            .lock()
            .unwrap()
            .iter()
            .find(|(_, c)| c.device == *device && c.stage != Stage::Idle)
            .map(|(h, _)| *h);
        if let Some(h) = handle {
            self.cancel(h);
        }
    }

    /// Re-encrypt an existing bond (we are the central).
    pub fn encrypt_bond(&self, handle: u16) -> Result<()> {
        let dev = self.device_of(handle).ok_or_else(|| Error::InvalidState("smp not attached".into()))?;
        let bond = self.bonds.get(&dev).ok_or_else(|| Error::NotFound("bond".into()))?;
        let Some(ltk) = bond.le_ltk else {
            return Err(Error::NotFound("le ltk".into()));
        };
        let mut p = handle.to_le_bytes().to_vec();
        p.extend_from_slice(&bond.le_rand.to_le_bytes());
        p.extend_from_slice(&bond.le_ediv.to_le_bytes());
        p.extend_from_slice(&ltk);
        let waiter = self.hci.expect_event(move |e| e.code == ev::ENCRYPTION_CHANGE && e.u16(1) == handle);
        self.hci.command_status(op::LE_START_ENCRYPTION, &p)?;
        let done = waiter.wait(Duration::from_secs(5))?;
        match done.u8(0) {
            0 => Ok(()),
            s => Err(Error::PairingFailed(format!("encryption failed: {}", hci_status_text(s)))),
        }
    }

    /// Begin legacy pairing (we are master/initiator).
    pub fn start_pairing(&self, handle: u16, mitm: bool) -> Result<()> {
        let auth = if mitm { AUTH_BONDING | AUTH_MITM } else { AUTH_BONDING };
        // opcode, IO capability, OOB, AuthReq, max key size, initiator key distribution, responder key distribution
        let preq: [u8; 7] = [0x01, IO_KEYBOARD_DISPLAY, 0x00, auth, 16, 0x00, KEYDIST_ENC | KEYDIST_ID];
        {
            let mut st = self.st.lock().unwrap();
            let c = st.get_mut(&handle).ok_or_else(|| Error::InvalidState("smp not attached".into()))?;
            if c.stage != Stage::Idle {
                return Err(Error::InvalidState("pairing already in progress".into()));
            }
            c.reset();
            c.preq = preq;
            c.stage = Stage::Requested;
        }
        if let Err(e) = self.l2.send_fixed(handle, CID_SMP, &preq) {
            if let Some(c) = self.st.lock().unwrap().get_mut(&handle) {
                c.reset();
            }
            return Err(e);
        }
        Ok(())
    }

    /// The user typed the passkey the peer displays.
    pub fn provide_passkey(&self, device: &DeviceId, passkey: u32) -> Result<()> {
        let handle = {
            let mut st = self.st.lock().unwrap();
            let (h, c) = st
                .iter_mut()
                .find(|(_, c)| c.device == *device && c.stage == Stage::WaitPasskey)
                .ok_or_else(|| Error::InvalidState("no pairing is waiting for a passkey".into()))?;
            c.tk = [0; 16];
            c.tk[..4].copy_from_slice(&(passkey % 1_000_000).to_le_bytes());
            *h
        };
        self.send_confirm(handle);
        Ok(())
    }

    fn on_smp(&self, handle: u16, data: &[u8]) {
        let Some(&code) = data.first() else { return };
        match code {
            0x02 => self.on_pairing_response(handle, data),
            0x03 => self.on_confirm(handle, data),
            0x04 => self.on_random(handle, data),
            0x05 => self.on_failed(handle, data),
            0x06..=0x0a => self.on_key(handle, code, data),
            0x0b => self.on_security_request(handle),
            _ => {
                // e.g. Secure Connections PDUs: tell the peer we only speak legacy pairing
                if self.busy(handle) {
                    self.fail(handle, Some(REASON_COMMAND_NOT_SUPPORTED), "unsupported smp command");
                } else {
                    let _ = self.l2.send_fixed(handle, CID_SMP, &[0x05, REASON_COMMAND_NOT_SUPPORTED]);
                }
            }
        }
    }

    fn on_security_request(&self, handle: u16) {
        let Some(dev) = self.device_of(handle) else { return };
        if self.bonds.get(&dev).is_some_and(|b| b.le_ltk.is_some()) {
            if let Err(e) = self.encrypt_bond(handle) {
                eprintln!("[smp] could not re-encrypt with the stored key: {e}");
            }
        } else if !self.busy(handle) {
            if let Err(e) = self.start_pairing(handle, true) {
                eprintln!("[smp] could not start pairing: {e}");
            }
        }
    }

    fn on_pairing_response(&self, handle: u16, data: &[u8]) {
        let Some(pres) = arr::<7>(data, 0) else {
            self.fail(handle, Some(REASON_INVALID_PARAMETERS), "malformed pairing response");
            return;
        };
        let (dev, preq) = {
            let mut st = self.st.lock().unwrap();
            let Some(c) = st.get_mut(&handle) else { return };
            if c.stage != Stage::Requested {
                return;
            }
            c.pres = pres;
            (c.device, c.preq)
        };
        if !(7..=16).contains(&pres[4]) {
            self.fail(handle, Some(REASON_ENC_KEY_SIZE), "peer offered an unusable encryption key size");
            return;
        }
        let mitm = (preq[3] | pres[3]) & AUTH_MITM != 0;
        // the keys the peer will hand over: its answer, limited to what we asked for
        let dist = pres[6] & preq[6];
        let mut expected = 0u8;
        if dist & KEYDIST_ENC != 0 {
            expected |= 0b0_0011; // LTK, EDIV+Rand
        }
        if dist & KEYDIST_ID != 0 {
            expected |= 0b0_1100; // IRK, identity address
        }
        if dist & KEYDIST_SIGN != 0 {
            expected |= 0b1_0000; // CSRK
        }
        let ask = |method: PairingMethod, passkey: Option<u32>| {
            self.bus.publish(Event::PairingRequested { request: PairingRequest { device: dev, method, passkey } });
        };
        let mut tk = [0u8; 16];
        match model_for(pres[1], mitm) {
            Model::JustWorks => ask(PairingMethod::JustWorks, None),
            Model::DisplayHere => {
                let Ok(r) = rand_u32() else {
                    self.fail(handle, Some(REASON_UNSPECIFIED), "no random source for the passkey");
                    return;
                };
                let passkey = r % 1_000_000;
                tk[..4].copy_from_slice(&passkey.to_le_bytes());
                ask(PairingMethod::JustWorks, Some(passkey)); // "display this passkey"
            }
            Model::EnterHere => {
                if let Some(c) = self.st.lock().unwrap().get_mut(&handle) {
                    c.expected = expected;
                    c.stage = Stage::WaitPasskey;
                }
                ask(PairingMethod::PasskeyEntry, None);
                return; // provide_passkey() continues from here
            }
        }
        if let Some(c) = self.st.lock().unwrap().get_mut(&handle) {
            c.tk = tk;
            c.expected = expected;
        }
        self.send_confirm(handle);
    }

    /// Mconfirm = c1(TK, Mrand, preq, pres, ...) — sent once the TK is known.
    fn send_confirm(&self, handle: u16) {
        let Ok(mrand) = rand16() else {
            self.fail(handle, Some(REASON_UNSPECIFIED), "no random source");
            return;
        };
        let confirm = {
            let mut st = self.st.lock().unwrap();
            let Some(c) = st.get_mut(&handle) else { return };
            let addrs = self.addrs_for(&c.device);
            c.mrand = mrand;
            c.stage = Stage::ConfirmSent;
            c1(&c.tk, &mrand, &c.preq, &c.pres, &addrs)
        };
        let mut pdu = vec![0x03];
        pdu.extend_from_slice(&confirm);
        if let Err(e) = self.l2.send_fixed(handle, CID_SMP, &pdu) {
            self.fail(handle, None, &e.to_string());
        }
    }

    /// The peer's Sconfirm arrived: reveal our Mrand.
    fn on_confirm(&self, handle: u16, data: &[u8]) {
        let Some(value) = arr::<16>(data, 1) else {
            self.fail(handle, Some(REASON_INVALID_PARAMETERS), "malformed pairing confirm");
            return;
        };
        let mrand = {
            let mut st = self.st.lock().unwrap();
            let Some(c) = st.get_mut(&handle) else { return };
            if c.stage != Stage::ConfirmSent {
                return;
            }
            c.peer_confirm = value;
            c.stage = Stage::RandomSent;
            c.mrand
        };
        let mut pdu = vec![0x04];
        pdu.extend_from_slice(&mrand);
        if let Err(e) = self.l2.send_fixed(handle, CID_SMP, &pdu) {
            self.fail(handle, None, &e.to_string());
        }
    }

    /// The peer's Srand arrived: check its confirm value, derive the STK and encrypt the link with it.
    fn on_random(&self, handle: u16, data: &[u8]) {
        let Some(srand) = arr::<16>(data, 1) else {
            self.fail(handle, Some(REASON_INVALID_PARAMETERS), "malformed pairing random");
            return;
        };
        let stk = {
            let mut st = self.st.lock().unwrap();
            let Some(c) = st.get_mut(&handle) else { return };
            if c.stage != Stage::RandomSent {
                return;
            }
            let addrs = self.addrs_for(&c.device);
            if c1(&c.tk, &srand, &c.preq, &c.pres, &addrs) != c.peer_confirm {
                None
            } else {
                let mut stk = s1(&c.tk, &srand, &c.mrand);
                let size = usize::from(c.preq[4].min(c.pres[4])).clamp(7, 16);
                stk[size..].fill(0); // honour the negotiated key size
                c.stage = Stage::Encrypting;
                Some(stk)
            }
        };
        let Some(stk) = stk else {
            self.fail(handle, Some(REASON_CONFIRM_FAILED), "pairing confirm value mismatch (wrong passkey?)");
            return;
        };
        // LE Start Encryption with the STK: Random_Number = 0, Encrypted_Diversifier = 0
        let mut p = handle.to_le_bytes().to_vec();
        p.extend_from_slice(&[0u8; 10]);
        p.extend_from_slice(&stk);
        if let Err(e) = self.hci.command_status(op::LE_START_ENCRYPTION, &p) {
            self.fail(handle, Some(REASON_UNSPECIFIED), &format!("could not start encryption: {e}"));
        }
    }

    fn on_failed(&self, handle: u16, data: &[u8]) {
        let reason = data.get(1).copied().unwrap_or(REASON_UNSPECIFIED);
        self.fail(handle, None, &format!("the device refused pairing (smp reason 0x{reason:02x})"));
    }

    /// HCI Encryption Change for an LE link: the STK took effect (or did not).
    pub fn on_encryption_change(&self, handle: u16, status: u8, enabled: bool) {
        let ok = {
            let mut st = self.st.lock().unwrap();
            match st.get_mut(&handle) {
                Some(c) if c.stage == Stage::Encrypting || c.stage == Stage::KeyDist => {
                    if status == 0 && enabled {
                        c.encrypted = true;
                        c.stage = Stage::KeyDist;
                        Some(true)
                    } else {
                        Some(false)
                    }
                }
                _ => None,
            }
        };
        match ok {
            Some(true) => self.finish_if_done(handle),
            Some(false) => {
                let why = format!("link encryption failed: {}", hci_status_text(status));
                self.fail(handle, None, &why);
            }
            None => {}
        }
    }

    /// Key distribution PDUs: 0x06 LTK, 0x07 EDIV+Rand, 0x08 IRK, 0x09 identity address, 0x0a CSRK.
    fn on_key(&self, handle: u16, code: u8, data: &[u8]) {
        {
            let mut st = self.st.lock().unwrap();
            let Some(c) = st.get_mut(&handle) else { return };
            if c.stage != Stage::Encrypting && c.stage != Stage::KeyDist {
                return;
            }
            let got = match code {
                0x06 => match arr::<16>(data, 1) {
                    Some(v) => {
                        c.keys.ltk = v;
                        true
                    }
                    None => false,
                },
                0x07 => match (arr::<2>(data, 1), arr::<8>(data, 3)) {
                    (Some(ediv), Some(rand)) => {
                        c.keys.ediv = u16::from_le_bytes(ediv);
                        c.keys.rand = u64::from_le_bytes(rand);
                        true
                    }
                    _ => false,
                },
                0x08 => match arr::<16>(data, 1) {
                    Some(v) => {
                        c.keys.irk = Some(v);
                        true
                    }
                    None => false,
                },
                0x09 => match (arr::<1>(data, 1), arr::<6>(data, 2)) {
                    (Some(t), Some(a)) => {
                        let address_type = if t[0] == 0 { AddressType::LePublic } else { AddressType::LeRandom };
                        c.keys.identity = Some(DeviceId { address: Address(a), address_type });
                        true
                    }
                    _ => false,
                },
                _ => match arr::<16>(data, 1) {
                    Some(v) => {
                        c.keys.csrk = Some(v);
                        true
                    }
                    None => false,
                },
            };
            if got {
                c.received |= 1 << (code - 0x06);
            }
        }
        self.finish_if_done(handle);
    }

    /// Pairing is complete once the link is encrypted and every promised key has arrived.
    fn finish_if_done(&self, handle: u16) {
        let done = {
            let mut st = self.st.lock().unwrap();
            match st.get_mut(&handle) {
                Some(c) if c.stage == Stage::KeyDist && c.encrypted && c.received == c.expected => {
                    let out = (c.device, c.keys.clone(), c.received & 0b0_0001 != 0);
                    c.reset();
                    Some(out)
                }
                _ => None,
            }
        };
        if let Some((device, keys, has_ltk)) = done {
            if has_ltk {
                self.bonds.upsert_le(&device, &keys, None);
            }
            self.bus.publish(Event::PairingComplete { id: device, success: true, error: None });
        }
    }

    /// HCI LE Long Term Key Request (peripheral-initiated encryption).
    pub fn on_ltk_request(&self, ev: &HciEvent) {
        let handle = ev.u16(1);
        let Some(dev) = self.device_of(handle) else {
            let _ = self.hci.command(op::LE_LTK_REQUEST_NEG_REPLY, &handle.to_le_bytes());
            return;
        };
        match self.bonds.get(&dev).and_then(|b| b.le_ltk) {
            Some(ltk) => {
                let mut p = handle.to_le_bytes().to_vec();
                p.extend_from_slice(&ltk);
                let _ = self.hci.command(op::LE_LTK_REQUEST_REPLY, &p);
            }
            None => {
                let _ = self.hci.command(op::LE_LTK_REQUEST_NEG_REPLY, &handle.to_le_bytes());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::from_hex;
    use crate::hci::{MockState, MockTransport};
    use crate::storage::Storage;

    /// Hex as printed in the Bluetooth spec (most significant byte first) -> little-endian byte array.
    fn le<const N: usize>(hex: &str) -> [u8; N] {
        let mut v = from_hex(hex).unwrap();
        v.reverse();
        v.try_into().unwrap()
    }

    fn be<const N: usize>(hex: &str) -> [u8; N] {
        from_hex(hex).unwrap().try_into().unwrap()
    }

    #[test]
    fn aes128_matches_fips197() {
        let out = aes128(&be::<16>("000102030405060708090a0b0c0d0e0f"), &be::<16>("00112233445566778899aabbccddeeff"));
        assert_eq!(out, be::<16>("69c4e0d86a7b0430d8cdb78070b4c55a"));
    }

    #[test]
    fn cmac_matches_rfc4493() {
        let key = be::<16>("2b7e151628aed2a6abf7158809cf4f3c");
        assert_eq!(aes_cmac(&key, &[]), be::<16>("bb1d6929e95937287fa37d129b756746"));
        let m16 = from_hex("6bc1bee22e409f96e93d7e117393172a").unwrap();
        assert_eq!(aes_cmac(&key, &m16), be::<16>("070a16b46b4d4144f79bdd9dd04a287c"));
        let m40 = from_hex(concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "30c81c46a35ce411"
        ))
        .unwrap();
        assert_eq!(aes_cmac(&key, &m40), be::<16>("dfa66747de9ae63030ca32611497c827"));
    }

    #[test]
    fn legacy_confirm_matches_the_spec_sample_data() {
        // Core Vol 3 Part H, Appendix D.2 (sample data prints values most significant byte first)
        let addrs = PairAddrs { iat: 1, ia: le::<6>("A1A2A3A4A5A6"), rat: 0, ra: le::<6>("B1B2B3B4B5B6") };
        let got = c1(
            &[0u8; 16],
            &le::<16>("5783D52156AD6F0E6388274EC6702EE0"),
            &le::<7>("07071000000101"),
            &le::<7>("05000800000302"),
            &addrs,
        );
        assert_eq!(got, le::<16>("1E1E3FEF878988EAD2A74DC5BEF13B86"));
    }

    #[test]
    fn stk_generation_matches_the_spec_sample_data() {
        let got = s1(
            &[0u8; 16],
            &le::<16>("000F0E0D0C0B0A091122334455667788"),
            &le::<16>("010203040506070899AABBCCDDEEFF00"),
        );
        assert_eq!(got, le::<16>("9A1FE1F0E8B0F49B5B4216AE796DA062"));
    }

    #[test]
    fn association_model_follows_the_io_capability_table() {
        assert_eq!(model_for(0x03, true), Model::JustWorks);
        assert_eq!(model_for(0x02, false), Model::JustWorks);
        assert_eq!(model_for(0x02, true), Model::DisplayHere);
        assert_eq!(model_for(0x00, true), Model::EnterHere);
        assert_eq!(model_for(0x01, true), Model::EnterHere);
        assert_eq!(model_for(0x04, true), Model::DisplayHere);
    }

    // --- an end-to-end run against a scripted peripheral ---

    const SMP_PDU: usize = 9; // 5 (ACL header) + 4 (L2CAP header)

    fn inbound_smp(handle: u16, pdu: &[u8]) -> Vec<u8> {
        let mut l2 = (pdu.len() as u16).to_le_bytes().to_vec();
        l2.extend_from_slice(&CID_SMP.to_le_bytes());
        l2.extend_from_slice(pdu);
        let mut acl = vec![0x02];
        acl.extend_from_slice(&(handle | 0x2000).to_le_bytes());
        acl.extend_from_slice(&(l2.len() as u16).to_le_bytes());
        acl.extend_from_slice(&l2);
        acl
    }

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

    #[test]
    fn just_works_pairing_derives_the_stk_and_stores_the_bond() {
        const HANDLE: u16 = 0x0040;
        let mock = MockTransport::new();
        let shared = mock.shared();
        let hci = Arc::new(HciClient::open(0, Box::new(mock)).unwrap());
        let l2 = L2cap::new(hci.clone());
        let dir = std::env::temp_dir().join(format!("mitos-smp-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let bonds = Arc::new(BondStore::new(Arc::new(Storage::new(&dir.to_string_lossy()).unwrap())));
        let bus = Arc::new(EventBus::new());
        let events = bus.subscribe();
        let own = Address([0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
        let smp = Smp::new(l2.clone(), hci.clone(), bus.clone(), bonds.clone(), own);
        let peer =
            DeviceId { address: Address([0xB6, 0xB5, 0xB4, 0xB3, 0xB2, 0xB1]), address_type: AddressType::LePublic };
        l2.set_device(HANDLE, peer);
        smp.attach(HANDLE, peer);

        // 1. we send a Pairing Request
        smp.start_pairing(HANDLE, false).unwrap();
        let sent = wait_acl(&shared, 1);
        let preq: [u8; 7] = sent[0][SMP_PDU..SMP_PDU + 7].try_into().unwrap();
        assert_eq!(preq, [0x01, 0x04, 0x00, 0x01, 16, 0x00, 0x03]);

        // 2. the peripheral (NoInputNoOutput, bonding, will distribute an LTK) answers: Just Works, TK = 0
        let pres: [u8; 7] = [0x02, 0x03, 0x00, 0x01, 16, 0x00, 0x01];
        shared.lock().unwrap().inject_event(inbound_smp(HANDLE, &pres));
        let sent = wait_acl(&shared, 2);
        assert_eq!(sent[1][SMP_PDU], 0x03); // our Pairing Confirm
        let mconfirm: [u8; 16] = sent[1][SMP_PDU + 1..SMP_PDU + 17].try_into().unwrap();

        // 3. the peripheral sends its confirm value for its random
        let addrs = PairAddrs { iat: 0, ia: own.0, rat: 0, ra: peer.address.0 };
        let srand = [0xA5u8; 16];
        let sconfirm = c1(&[0u8; 16], &srand, &preq, &pres, &addrs);
        let mut pdu = vec![0x03];
        pdu.extend_from_slice(&sconfirm);
        shared.lock().unwrap().inject_event(inbound_smp(HANDLE, &pdu));
        let sent = wait_acl(&shared, 3);
        assert_eq!(sent[2][SMP_PDU], 0x04); // our Pairing Random
        let mrand: [u8; 16] = sent[2][SMP_PDU + 1..SMP_PDU + 17].try_into().unwrap();
        assert_eq!(mconfirm, c1(&[0u8; 16], &mrand, &preq, &pres, &addrs)); // we committed to what we revealed

        // 4. the peripheral reveals Srand; we must start encryption with STK = s1(TK, Srand, Mrand)
        let mut pdu = vec![0x04];
        pdu.extend_from_slice(&srand);
        shared.lock().unwrap().inject_event(inbound_smp(HANDLE, &pdu));
        let stk = s1(&[0u8; 16], &srand, &mrand);
        let mut start_encryption = None;
        for _ in 0..400 {
            start_encryption = shared
                .lock()
                .unwrap()
                .sent_commands()
                .into_iter()
                .find(|c| c[1..3] == op::LE_START_ENCRYPTION.to_le_bytes());
            if start_encryption.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let cmd = start_encryption.expect("LE Start Encryption was not sent");
        assert_eq!(cmd[4..6], HANDLE.to_le_bytes());
        assert_eq!(cmd[6..16], [0u8; 10]); // Rand = 0, EDIV = 0 for the STK
        assert_eq!(cmd[16..32], stk);

        // 5. encryption comes up, then the peripheral distributes its LTK
        smp.on_encryption_change(HANDLE, 0, true);
        let ltk = [0x77u8; 16];
        let mut pdu = vec![0x06];
        pdu.extend_from_slice(&ltk);
        shared.lock().unwrap().inject_event(inbound_smp(HANDLE, &pdu));
        let mut pdu = vec![0x07];
        pdu.extend_from_slice(&0x1234u16.to_le_bytes());
        pdu.extend_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        shared.lock().unwrap().inject_event(inbound_smp(HANDLE, &pdu));

        let mut completed = false;
        while let Ok(ev) = events.recv_timeout(Duration::from_secs(3)) {
            if let Event::PairingComplete { id, success, .. } = ev {
                assert!(success);
                assert_eq!(id, peer);
                completed = true;
                break;
            }
        }
        assert!(completed, "pairing never completed");
        let bond = bonds.get(&peer).expect("bond was not stored");
        assert_eq!(bond.le_ltk, Some(ltk));
        assert_eq!(bond.le_ediv, 0x1234);
        assert_eq!(bond.le_rand, 0x1122_3344_5566_7788);
        assert!(!smp.busy(HANDLE));
        hci.shutdown();
    }
}
