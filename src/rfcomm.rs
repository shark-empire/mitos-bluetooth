use crate::error::{Error, Result};
use crate::l2cap::{L2Packet, L2cap, PSM_RFCOMM};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};

// ETSI TS 07.10 / Bluetooth RFCOMM frame types (control byte without the poll/final bit)
const SABM: u8 = 0x2f;
const UA: u8 = 0x63;
const DM: u8 = 0x0f;
const DISC: u8 = 0x43;
const UIH: u8 = 0xef;
const PF: u8 = 0x10;

/// Largest UIH payload when no parameter negotiation happened (N1 default).
const DEFAULT_N1: usize = 127;

/// Frame check sequence: reflected CRC-8, polynomial x^8+x^2+x+1 (0xE0 reflected), initial 0xFF, ones' complement.
fn fcs(bytes: &[u8]) -> u8 {
    let mut crc = 0xffu8;
    for &b in bytes {
        crc ^= b;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xe0 } else { crc >> 1 };
        }
    }
    0xff - crc
}

/// `cr` is the C/R bit: 1 on commands we send (we are the initiator) and on UIH data, 0 on our responses.
fn build_frame(dlci: u8, ctrl: u8, payload: &[u8], cr: bool, poll: bool) -> Vec<u8> {
    let mut f = Vec::with_capacity(payload.len() + 5);
    f.push((dlci << 2) | (u8::from(cr) << 1) | 1);
    f.push(if poll { ctrl | PF } else { ctrl });
    if payload.len() < 128 {
        f.push(((payload.len() as u8) << 1) | 1);
    } else {
        f.push(((payload.len() & 0x7f) as u8) << 1);
        f.push((payload.len() >> 7) as u8);
    }
    // UIH frames are protected over address+control only, all others also over the length
    let check = if ctrl == UIH { fcs(&f[..2]) } else { fcs(&f) };
    f.extend_from_slice(payload);
    f.push(check);
    f
}

struct Parsed {
    dlci: u8,
    ctrl: u8,
    payload: Vec<u8>,
}

fn parse_frame(d: &[u8]) -> Option<Parsed> {
    if d.len() < 4 {
        return None;
    }
    let dlci = d[0] >> 2;
    let ctrl = d[1] & !PF;
    let (len, off) = if d[2] & 1 == 1 {
        (usize::from(d[2] >> 1), 3)
    } else {
        (usize::from(d[2] >> 1) | (usize::from(*d.get(3)?) << 7), 4)
    };
    if d.len() < off + len + 1 {
        return None; // truncated: payload plus FCS must be present
    }
    Some(Parsed { dlci, ctrl, payload: d[off..off + len].to_vec() })
}

/// Multiplexer control commands travel as UIH on DLCI 0: [type][length][value...], where the type byte is
/// (kind << 2) | (C/R << 1) | EA. Returns the reply we owe the peer, if any.
fn mcc_reply(payload: &[u8]) -> Option<Vec<u8>> {
    let &ty = payload.first()?;
    if ty & 0x02 == 0 {
        return None; // a response to one of our own commands
    }
    Some(match ty >> 2 {
        // modem status, flow control on/off, test: echo the command back as a response (C/R cleared)
        0x38 | 0x28 | 0x18 | 0x08 => {
            let mut r = payload.to_vec();
            r[0] = ty & !0x02;
            r
        }
        // anything else (parameter negotiation, line status, ...): Non Supported Command response
        _ => vec![0x11, 0x03, ty],
    })
}

pub struct RfcommClient {
    pub cid: u16,
    dlci: u8,
    data_rx: Receiver<Vec<u8>>,
    closed: Arc<AtomicBool>,
}

impl RfcommClient {
    /// Establish the RFCOMM multiplexer + data DLC to a server channel (HFP/HSP devices).
    pub fn connect(l2: Arc<L2cap>, handle: u16, server_channel: u8) -> Result<Self> {
        let cid = l2.connect(handle, PSM_RFCOMM)?;
        let (data_tx, data_rx) = channel::<Vec<u8>>();
        let (evt_tx, evt_rx) = channel::<(u8, u8)>();
        let (mux_tx, mux_rx) = channel::<L2Packet>();
        l2.register_handler(cid, mux_tx);
        // We opened the multiplexer, so our direction bit is 0: DLCI = server channel << 1.
        let dlci = server_channel << 1;
        let closed = Arc::new(AtomicBool::new(false));

        // The pump starts first so that nothing the peer sends (UA, its own MSC, ...) can be lost.
        let pump_l2 = l2.clone();
        let pump_closed = closed.clone();
        std::thread::Builder::new()
            .name("rfcomm".into())
            .spawn(move || pump(mux_rx, pump_l2, cid, dlci, data_tx, evt_tx, pump_closed))
            .ok();

        if let Err(e) = open_channels(&l2, cid, dlci, &evt_rx) {
            let _ = l2.disconnect(cid); // also ends the pump
            return Err(e);
        }
        Ok(RfcommClient { cid, dlci, data_rx, closed })
    }

    pub fn send(&self, l2: &L2cap, data: &[u8]) -> Result<()> {
        if self.is_closed() {
            return Err(Error::InvalidState("rfcomm closed".into()));
        }
        for chunk in data.chunks(DEFAULT_N1) {
            l2.send(self.cid, &build_frame(self.dlci, UIH, chunk, true, false))?;
        }
        Ok(())
    }

    pub fn recv_timeout(&self, d: Duration) -> Result<Vec<u8>> {
        self.data_rx.recv_timeout(d).map_err(|_| Error::Timeout("rfcomm data"))
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }
}

/// 1. open the multiplexer (SABM on DLCI 0), 2. open the data DLC, 3. announce our modem status.
fn open_channels(l2: &L2cap, cid: u16, dlci: u8, evt_rx: &Receiver<(u8, u8)>) -> Result<()> {
    for d in [0, dlci] {
        l2.send(cid, &build_frame(d, SABM, &[], true, true))?;
        wait_event(evt_rx, d, UA)?;
    }
    // MSC command, length 2: DLCI, RTC|RTR|DV
    l2.send(cid, &build_frame(0, UIH, &[0xe3, 0x05, (dlci << 2) | 0x03, 0x8d], true, false))
}

/// Reads the L2CAP channel: forwards data, answers control traffic, reports UA/DM to `connect`.
fn pump(
    mux_rx: Receiver<L2Packet>,
    l2: Arc<L2cap>,
    cid: u16,
    dlci: u8,
    data_tx: Sender<Vec<u8>>,
    evt_tx: Sender<(u8, u8)>,
    closed: Arc<AtomicBool>,
) {
    while let Ok(p) = mux_rx.recv() {
        if p.closed {
            break;
        }
        let Some(f) = parse_frame(&p.data) else { continue };
        match f.ctrl {
            UIH if f.dlci == dlci => {
                let _ = data_tx.send(f.payload);
            }
            UIH if f.dlci == 0 => {
                if let Some(reply) = mcc_reply(&f.payload) {
                    let _ = l2.send(cid, &build_frame(0, UIH, &reply, true, false));
                }
            }
            UA | DM => {
                let _ = evt_tx.send((f.dlci, f.ctrl));
                if f.ctrl == DM && f.dlci == dlci {
                    break;
                }
            }
            DISC => {
                // we are the initiator: our responses carry C/R = 0
                let _ = l2.send(cid, &build_frame(f.dlci, UA, &[], false, true));
                if f.dlci == dlci || f.dlci == 0 {
                    break;
                }
            }
            _ => {}
        }
    }
    closed.store(true, Ordering::Relaxed);
}

fn wait_event(rx: &Receiver<(u8, u8)>, dlci: u8, expect: u8) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let (d, ctrl) = rx.recv_timeout(left).map_err(|_| Error::Timeout("rfcomm"))?;
        if d == dlci && ctrl == expect {
            return Ok(());
        }
        if d == dlci && ctrl == DM {
            return Err(Error::ConnectionFailed("rfcomm channel refused (DM)".into()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_frames_carry_the_spec_fcs() {
        // the well-known multiplexer start-up frames
        assert_eq!(build_frame(0, SABM, &[], true, true), vec![0x03, 0x3f, 0x01, 0x1c]);
        assert_eq!(build_frame(0, UA, &[], true, true), vec![0x03, 0x73, 0x01, 0xd7]);
    }

    #[test]
    fn uih_data_frame_layout() {
        // channel 1 -> DLCI 2, initiator command: address 0x0b; UIH is checked over address+control only
        let f = build_frame(2, UIH, b"AT\r", true, false);
        assert_eq!(f[..5], [0x0b, 0xef, 0x07, b'A', b'T']);
        assert_eq!(f[5], b'\r');
        assert_eq!(f[6], 0x9a);
        let p = parse_frame(&f).unwrap();
        assert_eq!((p.dlci, p.ctrl), (2, UIH));
        assert_eq!(p.payload, b"AT\r");
    }

    #[test]
    fn long_payloads_use_a_two_byte_length() {
        let data = vec![7u8; 200];
        let f = build_frame(4, UIH, &data, true, false);
        assert_eq!(f[2..4], [0x90, 0x01]); // (200 & 0x7f) << 1 with EA = 0, then 200 >> 7
        let p = parse_frame(&f).unwrap();
        assert_eq!(p.payload.len(), 200);
        assert!(parse_frame(&f[..f.len() - 3]).is_none()); // truncated frames are rejected
    }

    #[test]
    fn multiplexer_commands_are_answered() {
        // MSC command -> same MSC as a response (C/R cleared)
        assert_eq!(mcc_reply(&[0xe3, 0x05, 0x0b, 0x8d]), Some(vec![0xe1, 0x05, 0x0b, 0x8d]));
        // parameter negotiation is not supported: Non Supported Command naming the command type
        assert_eq!(mcc_reply(&[0x83, 0x11, 0, 0]), Some(vec![0x11, 0x03, 0x83]));
        // a response to our own MSC needs no answer
        assert_eq!(mcc_reply(&[0xe1, 0x05, 0x0b, 0x8d]), None);
        assert_eq!(mcc_reply(&[]), None);
    }
}
