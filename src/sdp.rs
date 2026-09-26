use crate::error::{Error, Result};
use crate::l2cap::{L2Packet, L2cap, PSM_SDP};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::time::Duration;

#[derive(Default, Debug, Clone)]
pub struct SdpService {
    pub psm: Option<u16>,
    pub rfcomm_channel: Option<u8>,
    pub name: Option<String>,
    pub version: Option<u16>,
    pub hid_descriptor: Option<Vec<u8>>,
    pub service_classes: Vec<u16>,
}

#[derive(Debug, Clone)]
pub enum De { U(u128), Uuid(u128), Str(Vec<u8>), Bool(bool), Seq(Vec<De>) }

/// SDP data elements are big-endian.
pub fn parse_de(b: &[u8], i: &mut usize) -> Result<De> {
    if *i >= b.len() { return Err(Error::Sdp("truncated data element".into())); }
    let h = b[*i]; *i += 1;
    let ty = h >> 3; let sz = h & 7;
    let (len, extra) = match sz {
        0 => (1usize, 0usize), 1 => (2, 0), 2 => (4, 0), 3 => (8, 0), 4 => (16, 0),
        5 => { *i += 1; (b.get(*i - 1).copied().unwrap_or(0) as usize, 1) }
        6 => { let l = u16::from_be_bytes([*b.get(*i).unwrap_or(&0), *b.get(*i + 1).unwrap_or(&0)]) as usize; *i += 2; (l, 2) }
        _ => { let l = u32::from_be_bytes([*b.get(*i).unwrap_or(&0), *b.get(*i+1).unwrap_or(&0), *b.get(*i+2).unwrap_or(&0), *b.get(*i+3).unwrap_or(&0)]) as usize; *i += 4; (l, 4) }
    };
    let start = *i;
    let end = (start + len).min(b.len());
    let val = match ty {
        0 => De::U(0),
        1 => { let mut v = 0u128; for x in &b[start..end] { v = (v << 8) | *x as u128 } De::U(v) }
        2 => { let mut v = 0i128; for x in &b[start..end] { v = (v << 8) | *x as i128 } if !b[start..end].is_empty() && b[start] & 0x80 != 0 && len < 16 { v -= 1i128 << (len * 8) } De::U(v as u128) }
        3 => { let mut v = 0u128; for x in &b[start..end] { v = (v << 8) | *x as u128 } De::Uuid(v) }
        4 => De::Str(b[start..end].to_vec()),
        5 => De::Bool(b.get(start).copied().unwrap_or(0) == 1),
        6 | 7 => {
            let mut kids = Vec::new();
            let real_end = start + len;
            while *i < real_end && *i < b.len() { kids.push(parse_de(b, i)?); }
            De::Seq(kids)
        }
        _ => De::U(0),
    };
    *i = end.max(*i);
    if ty >= 6 { *i = start + len; }
    Ok(val)
}

pub struct SdpClient { l2: Arc<L2cap>, handle: u16, cid: u16, tid: u16, rx: Receiver<L2Packet> }

impl SdpClient {
    pub fn connect(l2: Arc<L2cap>, handle: u16) -> Result<Self> {
        let cid = l2.connect(handle, PSM_SDP)?;
        let (tx, rx) = channel();
        l2.register_handler(cid, tx);
        Ok(SdpClient { l2, handle, cid, tid: 1, rx })
    }

    /// Service Search Attribute request for a 16-bit service class UUID.
    pub fn query(&mut self, uuid16: u16) -> Result<SdpService> {
        let mut cont: Vec<u8> = Vec::new();
        let mut attrs: Vec<u8> = Vec::new();
        for _ in 0..8 {
            let params = self.build_ssa(uuid16, &cont);
            let resp = self.transaction(0x06, &params)?;
            if resp.len() < 3 { return Err(Error::Sdp("short response".into())); }
            let count = u16::from_be_bytes([resp[0], resp[1]]) as usize;
            let body_end = (2 + count).min(resp.len());
            attrs.extend_from_slice(&resp[2..body_end]);
            let cl = resp.get(body_end).copied().unwrap_or(0) as usize;
            cont = resp.get(body_end + 1..body_end + 1 + cl).unwrap_or(&[]).to_vec();
            if cont.is_empty() { break; }
        }
        self.parse_attrs(&attrs)
    }

    fn build_ssa(&self, uuid16: u16, cont: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&[0x35, 0x03, 0x19, 0x02]); // seq(uuid16)
        p.extend_from_slice(&uuid16.to_be_bytes());
        p.extend_from_slice(&[0x08, 0x02]); // uint16 max attr byte count
        p.extend_from_slice(&0xFFFFu16.to_be_bytes());
        p.extend_from_slice(&[0x35, 0x06, 0x0a]); // seq(uint32 range 0x0000-0xFFFF)
        p.extend_from_slice(&0x0000u32.to_be_bytes());
        p.extend_from_slice(&0xFFFFu32.to_be_bytes());
        p.push(cont.len() as u8);
        p.extend_from_slice(cont);
        p
    }

    fn transaction(&mut self, pdu: u8, params: &[u8]) -> Result<Vec<u8>> {
        let tid = self.tid;
        self.tid = self.tid.wrapping_add(1);
        let mut pkt = vec![pdu];
        pkt.extend_from_slice(&tid.to_be_bytes());
        pkt.extend_from_slice(&(params.len() as u16).to_be_bytes());
        pkt.extend_from_slice(params);
        self.l2.send(self.cid, &pkt)?;
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            match self.rx.recv_timeout(deadline - std::time::Instant::now()) {
                Ok(p) if p.closed => return Err(Error::Sdp("sdp channel closed".into())),
                Ok(p) => {
                    let d = &p.data;
                    if d.len() >= 5 && d[0] == pdu + 1 && u16::from_be_bytes([d[1], d[2]]) == tid {
                        return Ok(d[5..].to_vec());
                    }
                }
                Err(_) => return Err(Error::Timeout("sdp response")),
            }
        }
        Err(Error::Timeout("sdp response"))
    }

    fn parse_attrs(&self, raw: &[u8]) -> Result<SdpService> {
        let mut svc = SdpService::default();
        let mut i = 0;
        while i < raw.len() {
            let id = match parse_de(raw, &mut i)? { De::U(v) => v as u16, _ => break };
            let val = parse_de(raw, &mut i)?;
            match id {
                0x0001 => { // ServiceClassIDList
                    if let De::Seq(items) = val {
                        for it in items { if let De::Uuid(u) = it { svc.service_classes.push(u as u16); } }
                    }
                }
                0x0004 => { // ProtocolDescriptorList
                    if let De::Seq(layers) = val {
                        for layer in layers {
                            let De::Seq(parts) = layer else { continue };
                            let mut it = parts.iter();
                            let uuid = match it.next() { Some(De::Uuid(u)) => u as u16, _ => continue };
                            match uuid {
                                0x0100 => { if let Some(De::U(p)) = it.next() { if svc.psm.is_none() { svc.psm = Some(p as u16); } } } // L2CAP
                                0x0003 => { if let Some(De::U(c)) = it.next() { if svc.rfcomm_channel.is_none() { svc.rfcomm_channel = Some(c as u8); } } } // RFCOMM
                                _ => {}
                            }
                        }
                    }
                }
                0x0009 => { // ProfileDescriptorList: [[uuid, version]]
                    if let De::Seq(items) = val {
                        if let Some(De::Seq(pair)) = items.first() {
                            if pair.len() == 2 { if let (De::Uuid(_), De::U(v)) = (&pair[0], &pair[1]) { svc.version = Some(*v as u16); } }
                        }
                    }
                }
                0x0100 => { if let De::Str(s) = val { svc.name = Some(String::from_utf8_lossy(&s).to_string()); } }
                0x0206 => { // HIDDescriptorList: [[type(0x22), data]]
                    if let De::Seq(items) = val {
                        for item in items {
                            if let De::Seq(pair) = item {
                                if pair.len() == 2 {
                                    if let (De::U(t), De::Str(d)) = (&pair[0], &pair[1]) {
                                        if *t as u16 == 0x22 { svc.hid_descriptor = Some(d.clone()); }
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(svc)
    }
}

impl Drop for SdpClient {
    fn drop(&mut self) { let _ = self.l2.disconnect(self.cid); }
}